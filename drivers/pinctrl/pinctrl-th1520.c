// SPDX-License-Identifier: GPL-2.0
/*
 * Pinctrl driver for the XuanTie TH1520 SoC
 *
 * Copyright (C) 2023 Emil Renner Berthing <emil.renner.berthing@canonical.com>
 */

#include <linux/bits.h>
#include <linux/cleanup.h>
#include <linux/clk.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/clk.h>

#include <linux/pinctrl/pinconf.h>
#include <linux/pinctrl/pinconf-generic.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinmux.h>

#include "core.h"
#include "pinmux.h"
#include "pinconf.h"

#define TH1520_PADCFG_IE	BIT(9)
#define TH1520_PADCFG_SL	BIT(8)
#define TH1520_PADCFG_ST	BIT(7)
#define TH1520_PADCFG_SPU	BIT(6)
#define TH1520_PADCFG_PS	BIT(5)
#define TH1520_PADCFG_PE	BIT(4)
#define TH1520_PADCFG_BIAS	(TH1520_PADCFG_SPU | TH1520_PADCFG_PS | TH1520_PADCFG_PE)
#define TH1520_PADCFG_DS	GENMASK(3, 0)

#define TH1520_PULL_DOWN_OHM	44000 /* typ. 44kOhm */
#define TH1520_PULL_UP_OHM	48000 /* typ. 48kOhm */
#define TH1520_PULL_STRONG_OHM	 2100 /* typ. 2.1kOhm */

#define TH1520_PAD_NO_PADCFG	BIT(30)
#define TH1520_PAD_MUXDATA	GENMASK(29, 0)

#ifdef CONFIG_PM_SLEEP
#define MAX_CFG_REG_NUMS	32
#define MAX_MUX_REG_NUMS	8
#define TH1520_PADCTRL0_CFG_REG_NUMS	28
#define TH1520_PADCTRL0_MUX_REG_NUMS	7
#define TH1520_PADCTRL1_CFG_REG_NUMS	32
#define TH1520_PADCTRL1_MUX_REG_NUMS	8
#define TH1520_AON_CFG_REG_NUMS		24
#define TH1520_AON_MUX_REG_NUMS		6
#define TH1520_AUDIO_CFG_REG_NUMS	16
#define TH1520_AUDIO_MUX_REG_NUMS	2
#define TH1520_AUDIO_IO_SEL_IDX		2
#define TH1520_PM_PAD_CFG(idx)		(thp->base + thp->offset_cfg + idx * 4)
#define TH1520_PM_PAD_MUX(idx)		(thp->base +  thp->offset_mux + idx * 4)
#endif

struct th1520_pinctrl;

struct custom_operations {
	int (*init)(struct th1520_pinctrl *thp, unsigned int pin);
};

enum th1520_pinctrl_type {
	TH1520_PADCTRL_0,
	TH1520_PADCTRL_1,
	TH1520_PADCTRL_AON,
	TH1520_PADCTRL_AUDIO,
};

struct th1520_pad_group {
	const char *name;
	const struct pinctrl_pin_desc *pins;
	unsigned int npins;
	unsigned int offset_mux;
	unsigned int mask_mux;
	unsigned int offset_cfg;
	unsigned int mask_cfg;
	enum th1520_pinctrl_type type;
	struct custom_operations *custom_ops;
};

struct th1520_pinctrl {
	struct pinctrl_desc desc;
	struct mutex mutex;	/* serialize adding functions */
	raw_spinlock_t lock;	/* serialize register access */
	void __iomem *base;
	struct clk	*clk;
	unsigned int offset_mux;
	unsigned int mask_mux;
	unsigned int offset_cfg;
	unsigned int mask_cfg;
	struct custom_operations *custom_ops;
	enum th1520_pinctrl_type type;
	struct pinctrl_dev *pctl;
#ifdef CONFIG_PM_SLEEP
	unsigned int cfg_bak[MAX_CFG_REG_NUMS];
	unsigned int mux_bak[MAX_MUX_REG_NUMS];
#endif
};

static const unsigned int m1  = 0x55555555; // 01010101010101010101010101010101
static const unsigned int m2  = 0x33333333; // 00110011001100110011001100110011
static const unsigned int m4  = 0x0f0f0f0f; // 00001111000011110000111100001111
static const unsigned int m8  = 0x00ff00ff; // 00000000111111110000000011111111
static const unsigned int m16 = 0x0000ffff; // 00000000000000001111111111111111

static int __popcount(unsigned int x)
{
	x = (x & m1) + ((x >> 1) & m1);
	x = (x & m2) + ((x >> 2) & m2);
	x = (x & m4) + ((x >> 4) & m4);
	x = (x & m8) + ((x >> 8) & m8);
	x = (x & m16) + ((x >> 16) & m16);
	return x;
}

static void __iomem *th1520_padcfg(struct th1520_pinctrl *thp,
				   unsigned int pin)
{
	int width = __popcount(thp->mask_cfg);

	return thp->base + thp->offset_cfg + 4 * (pin * width / 32);
}

static unsigned int th1520_padcfg_shift(struct th1520_pinctrl *thp,
					unsigned int pin)
{
	int width = __popcount(thp->mask_cfg);

	return width * (pin & (32 / width - 1));
}

static void __iomem *th1520_muxcfg(struct th1520_pinctrl *thp,
					unsigned int pin)
{
	int width = __popcount(thp->mask_mux);

	return thp->base + thp->offset_mux + 4 * (pin * width / 32);
}

static unsigned int th1520_muxcfg_shift(struct th1520_pinctrl *thp,
					unsigned int pin)
{
	int width = __popcount(thp->mask_mux);

	return width * (pin & (32 / width - 1));
}

static int th1520_audio_func_sel(struct th1520_pinctrl *thp,
					unsigned int pin)
{
	void __iomem *padsel = thp->base;
	unsigned int tmp;

	scoped_guard(raw_spinlock_irqsave, &thp->lock) {
		tmp = readl_relaxed(padsel);
		tmp |= 1 << pin;
		writel_relaxed(tmp, padsel);
	}
	return 0;
}

static struct custom_operations th1520_custom_ops = {
	.init = th1520_audio_func_sel,
};

enum th1520_muxtype {
	TH1520_MUX_____,
	TH1520_MUX_GPIO,
	TH1520_MUX_PWM,
	TH1520_MUX_UART,
	TH1520_MUX_I2C,
	TH1520_MUX_SPI,
	TH1520_MUX_QSPI,
	TH1520_MUX_SDIO,
	TH1520_MUX_AUD,
	TH1520_MUX_I2S,
	TH1520_MUX_MAC0,
	TH1520_MUX_MAC1,
	TH1520_MUX_DPU0,
	TH1520_MUX_DPU1,
	TH1520_MUX_ISP,
	TH1520_MUX_HDMI,
	TH1520_MUX_CLK,
	TH1520_MUX_JTAG,
	TH1520_MUX_ISO,
	TH1520_MUX_FUSE,
	TH1520_MUX_RST,
	TH1520_MUX_AUD_VAD,
	TH1520_MUX_AUD_VAD_PDM,
	TH1520_MUX_AUD_I2C0,
	TH1520_MUX_AUD_I2C1,
	TH1520_MUX_AUD_I2S0,
	TH1520_MUX_AUD_I2S1,
	TH1520_MUX_AUD_I2S2,
	TH1520_MUX_AUD_I2S_8CH,
	TH1520_MUX_AUD_TDM,
	TH1520_MUX_AUD_SPDIF0,
	TH1520_MUX_AUD_SPDIF1,
	TH1520_MUX_MAX = 31, // [4:0]
};

static const char *const th1520_muxtype_string[] = {
	[TH1520_MUX_GPIO] = "gpio",
	[TH1520_MUX_PWM]  = "pwm",
	[TH1520_MUX_UART] = "uart",
	[TH1520_MUX_I2C]  = "i2c",
	[TH1520_MUX_SPI]  = "spi",
	[TH1520_MUX_QSPI] = "qspi",
	[TH1520_MUX_SDIO] = "sdio",
	[TH1520_MUX_AUD]  = "audio",
	[TH1520_MUX_I2S]  = "i2s",
	[TH1520_MUX_MAC0] = "gmac0",
	[TH1520_MUX_MAC1] = "gmac1",
	[TH1520_MUX_DPU0] = "dpu0",
	[TH1520_MUX_DPU1] = "dpu1",
	[TH1520_MUX_ISP]  = "isp",
	[TH1520_MUX_HDMI] = "hdmi",
	[TH1520_MUX_CLK]  = "clock",
	[TH1520_MUX_JTAG] = "jtag",
	[TH1520_MUX_ISO]  = "iso7816",
	[TH1520_MUX_FUSE] = "efuse",
	[TH1520_MUX_RST]  = "reset",
	[TH1520_MUX_AUD_VAD]      = "aud_vad",
	[TH1520_MUX_AUD_VAD_PDM]  = "aud_vad_pdm",
	[TH1520_MUX_AUD_I2C0]     = "aud_i2c0",
	[TH1520_MUX_AUD_I2C1]     = "aud_i2c1",
	[TH1520_MUX_AUD_I2S0]     = "aud_i2s0",
	[TH1520_MUX_AUD_I2S1]     = "aud_i2s1",
	[TH1520_MUX_AUD_I2S2]     = "aud_i2s2",
	[TH1520_MUX_AUD_I2S_8CH]  = "aud_i2s_8ch",
	[TH1520_MUX_AUD_TDM]      = "aud_tdm",
	[TH1520_MUX_AUD_SPDIF0]   = "aud_spdif0",
	[TH1520_MUX_AUD_SPDIF1]   = "aud_spdif1",
};

static enum th1520_muxtype th1520_muxtype_get(const char *str)
{
	enum th1520_muxtype mt;

	for (mt = TH1520_MUX_GPIO; mt < ARRAY_SIZE(th1520_muxtype_string); mt++) {
		if (!strcmp(str, th1520_muxtype_string[mt]))
			return mt;
	}
	return TH1520_MUX_____;
}

#define TH1520_PAD(_nr, _name, m0, m1, m2, m3, m4, m5, _flags) \
	{ .number = _nr, .name = #_name, .drv_data = (void *)((_flags) | \
		(TH1520_MUX_##m0 <<  0) | (TH1520_MUX_##m1 <<  5) | (TH1520_MUX_##m2 << 10) | \
		(TH1520_MUX_##m3 << 15) | (TH1520_MUX_##m4 << 20) | (TH1520_MUX_##m5 << 25)) }

static const struct pinctrl_pin_desc th1520_group1_pins[] = {
	TH1520_PAD(0,  OSC_CLK_IN,    ____, ____, ____, ____, ____, ____, TH1520_PAD_NO_PADCFG),
	TH1520_PAD(1,  OSC_CLK_OUT,   ____, ____, ____, ____, ____, ____, TH1520_PAD_NO_PADCFG),
	TH1520_PAD(2,  SYS_RST_N,     ____, ____, ____, ____, ____, ____, TH1520_PAD_NO_PADCFG),
	TH1520_PAD(3,  RTC_CLK_IN,    ____, ____, ____, ____, ____, ____, TH1520_PAD_NO_PADCFG),
	TH1520_PAD(4,  RTC_CLK_OUT,   ____, ____, ____, ____, ____, ____, TH1520_PAD_NO_PADCFG),
	/* skip number 5 so we can calculate register offsets and shifts from the pin number */
	TH1520_PAD(6,  TEST_MODE,     ____, ____, ____, ____, ____, ____, TH1520_PAD_NO_PADCFG),
	TH1520_PAD(7,  DEBUG_MODE,    ____, ____, ____, GPIO, ____, ____, TH1520_PAD_NO_PADCFG),
	TH1520_PAD(8,  POR_SEL,       ____, ____, ____, ____, ____, ____, TH1520_PAD_NO_PADCFG),
	TH1520_PAD(9,  I2C_AON_SCL,   I2C,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(10, I2C_AON_SDA,   I2C,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(11, CPU_JTG_TCLK,  JTAG, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(12, CPU_JTG_TMS,   JTAG, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(13, CPU_JTG_TDI,   JTAG, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(14, CPU_JTG_TDO,   JTAG, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(15, CPU_JTG_TRST,  JTAG, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(16, AOGPIO_7,      CLK,  AUD,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(17, AOGPIO_8,      UART, AUD,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(18, AOGPIO_9,      UART, AUD,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(19, AOGPIO_10,     CLK,  AUD,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(20, AOGPIO_11,     GPIO, AUD,  ____, ____, ____, ____, 0),
	TH1520_PAD(21, AOGPIO_12,     GPIO, AUD,  ____, ____, ____, ____, 0),
	TH1520_PAD(22, AOGPIO_13,     GPIO, AUD,  ____, ____, ____, ____, 0),
	TH1520_PAD(23, AOGPIO_14,     GPIO, AUD,  ____, ____, ____, ____, 0),
	TH1520_PAD(24, AOGPIO_15,     GPIO, AUD,  ____, ____, ____, ____, 0),
	TH1520_PAD(25, AUDIO_PA0,     AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(26, AUDIO_PA1,     AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(27, AUDIO_PA2,     AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(28, AUDIO_PA3,     AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(29, AUDIO_PA4,     AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(30, AUDIO_PA5,     AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(31, AUDIO_PA6,     AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(32, AUDIO_PA7,     AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(33, AUDIO_PA8,     AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(34, AUDIO_PA9,     AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(35, AUDIO_PA10,    AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(36, AUDIO_PA11,    AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(37, AUDIO_PA12,    AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(38, AUDIO_PA13,    AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(39, AUDIO_PA14,    AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(40, AUDIO_PA15,    AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(41, AUDIO_PA16,    AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(42, AUDIO_PA17,    AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(43, AUDIO_PA27,    AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(44, AUDIO_PA28,    AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(45, AUDIO_PA29,    AUD,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(46, AUDIO_PA30,    AUD,  RST,  ____, GPIO, ____, ____, 0),
};

static const struct pinctrl_pin_desc th1520_group2_pins[] = {
	TH1520_PAD(0,  QSPI1_SCLK,    QSPI, ISO,  ____, GPIO, FUSE, ____, 0),
	TH1520_PAD(1,  QSPI1_CSN0,    QSPI, ____, I2C,  GPIO, FUSE, ____, 0),
	TH1520_PAD(2,  QSPI1_D0_MOSI, QSPI, ISO,  I2C,  GPIO, FUSE, ____, 0),
	TH1520_PAD(3,  QSPI1_D1_MISO, QSPI, ISO,  ____, GPIO, FUSE, ____, 0),
	TH1520_PAD(4,  QSPI1_D2_WP,   QSPI, ISO,  UART, GPIO, FUSE, ____, 0),
	TH1520_PAD(5,  QSPI1_D3_HOLD, QSPI, ISO,  UART, GPIO, ____, ____, 0),
	TH1520_PAD(6,  I2C0_SCL,      I2C,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(7,  I2C0_SDA,      I2C,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(8,  I2C1_SCL,      I2C,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(9,  I2C1_SDA,      I2C,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(10, UART1_TXD,     UART, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(11, UART1_RXD,     UART, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(12, UART4_TXD,     UART, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(13, UART4_RXD,     UART, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(14, UART4_CTSN,    UART, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(15, UART4_RTSN,    UART, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(16, UART3_TXD,     ____, UART, ____, GPIO, ____, ____, 0),
	TH1520_PAD(17, UART3_RXD,     ____, UART, ____, GPIO, ____, ____, 0),
	TH1520_PAD(18, GPIO0_18,      GPIO, I2C,  ____, ____, ____, ____, 0),
	TH1520_PAD(19, GPIO0_19,      GPIO, I2C,  ____, ____, ____, ____, 0),
	TH1520_PAD(20, GPIO0_20,      GPIO, UART, ____, ____, ____, ____, 0),
	TH1520_PAD(21, GPIO0_21,      GPIO, UART, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(22, GPIO0_22,      GPIO, JTAG, I2C,  ____, DPU0, DPU1, 0),
	TH1520_PAD(23, GPIO0_23,      GPIO, JTAG, I2C,  ____, DPU0, DPU1, 0),
	TH1520_PAD(24, GPIO0_24,      GPIO, JTAG, QSPI, ____, DPU0, DPU1, 0),
	TH1520_PAD(25, GPIO0_25,      GPIO, JTAG, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(26, GPIO0_26,      GPIO, JTAG, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(27, GPIO0_27,      GPIO, ____, I2C,  ____, DPU0, DPU1, 0),
	TH1520_PAD(28, GPIO0_28,      GPIO, ____, I2C,  ____, DPU0, DPU1, 0),
	TH1520_PAD(29, GPIO0_29,      GPIO, ____, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(30, GPIO0_30,      GPIO, ____, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(31, GPIO0_31,      GPIO, ____, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(32, GPIO1_0,       GPIO, JTAG, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(33, GPIO1_1,       GPIO, JTAG, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(34, GPIO1_2,       GPIO, JTAG, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(35, GPIO1_3,       GPIO, JTAG, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(36, GPIO1_4,       GPIO, JTAG, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(37, GPIO1_5,       GPIO, ____, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(38, GPIO1_6,       GPIO, ____, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(39, GPIO1_7,       GPIO, QSPI, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(40, GPIO1_8,       GPIO, QSPI, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(41, GPIO1_9,       GPIO, QSPI, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(42, GPIO1_10,      GPIO, QSPI, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(43, GPIO1_11,      GPIO, QSPI, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(44, GPIO1_12,      GPIO, QSPI, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(45, GPIO1_13,      GPIO, UART, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(46, GPIO1_14,      GPIO, UART, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(47, GPIO1_15,      GPIO, UART, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(48, GPIO1_16,      GPIO, UART, ____, ____, DPU0, DPU1, 0),
	TH1520_PAD(49, CLK_OUT_0,     ____, CLK,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(50, CLK_OUT_1,     ____, CLK,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(51, CLK_OUT_2,     ____, CLK,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(52, CLK_OUT_3,     ____, CLK,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(53, GPIO1_21,      GPIO, ____, ISP,  ____, ____, ____, 0),
	TH1520_PAD(54, GPIO1_22,      GPIO, ____, ISP,  ____, ____, ____, 0),
	TH1520_PAD(55, GPIO1_23,      GPIO, ____, ISP,  ____, ____, ____, 0),
	TH1520_PAD(56, GPIO1_24,      JTAG, ____, ISP,  GPIO, ____, ____, 0),
	TH1520_PAD(57, GPIO1_25,      JTAG, ____, ISP,  GPIO, ____, ____, 0),
	TH1520_PAD(58, GPIO1_26,      GPIO, ____, ISP,  ____, ____, ____, 0),
	TH1520_PAD(59, GPIO1_27,      GPIO, ____, ISP,  ____, ____, ____, 0),
	TH1520_PAD(60, GPIO1_28,      GPIO, ____, ISP,  ____, ____, ____, 0),
	TH1520_PAD(61, GPIO1_29,      GPIO, ____, ISP,  ____, ____, ____, 0),
	TH1520_PAD(62, GPIO1_30,      GPIO, ____, ISP,  ____, ____, ____, 0),
};

static const struct pinctrl_pin_desc th1520_group3_pins[] = {
	TH1520_PAD(0,  UART0_TXD,     UART, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(1,  UART0_RXD,     UART, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(2,  QSPI0_SCLK,    QSPI, PWM,  I2S,  GPIO, ____, ____, 0),
	TH1520_PAD(3,  QSPI0_CSN0,    QSPI, PWM,  I2S,  GPIO, ____, ____, 0),
	TH1520_PAD(4,  QSPI0_CSN1,    QSPI, PWM,  I2S,  GPIO, ____, ____, 0),
	TH1520_PAD(5,  QSPI0_D0_MOSI, QSPI, PWM,  I2S,  GPIO, ____, ____, 0),
	TH1520_PAD(6,  QSPI0_D1_MISO, QSPI, PWM,  I2S,  GPIO, ____, ____, 0),
	TH1520_PAD(7,  QSPI0_D2_WP,   QSPI, PWM,  I2S,  GPIO, ____, ____, 0),
	TH1520_PAD(8,  QSPI0_D3_HOLD, QSPI, ____, I2S,  GPIO, ____, ____, 0),
	TH1520_PAD(9,  I2C2_SCL,      I2C,  UART, ____, GPIO, ____, ____, 0),
	TH1520_PAD(10, I2C2_SDA,      I2C,  UART, ____, GPIO, ____, ____, 0),
	TH1520_PAD(11, I2C3_SCL,      I2C,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(12, I2C3_SDA,      I2C,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(13, GPIO2_13,      GPIO, SPI,  ____, ____, ____, ____, 0),
	TH1520_PAD(14, SPI_SCLK,      SPI,  UART, ____, GPIO, ____, ____, 0),
	TH1520_PAD(15, SPI_CSN,       SPI,  UART, ____, GPIO, ____, ____, 0),
	TH1520_PAD(16, SPI_MOSI,      SPI,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(17, SPI_MISO,      SPI,  ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(18, GPIO2_18,      GPIO, MAC1, ____, ____, ____, ____, 0),
	TH1520_PAD(19, GPIO2_19,      GPIO, MAC1, ____, ____, ____, ____, 0),
	TH1520_PAD(20, GPIO2_20,      GPIO, MAC1, ____, ____, ____, ____, 0),
	TH1520_PAD(21, GPIO2_21,      GPIO, MAC1, ____, ____, ____, ____, 0),
	TH1520_PAD(22, GPIO2_22,      GPIO, MAC1, ____, ____, ____, ____, 0),
	TH1520_PAD(23, GPIO2_23,      GPIO, MAC1, ____, ____, ____, ____, 0),
	TH1520_PAD(24, GPIO2_24,      GPIO, MAC1, ____, ____, ____, ____, 0),
	TH1520_PAD(25, GPIO2_25,      GPIO, MAC1, ____, ____, ____, ____, 0),
	TH1520_PAD(26, SDIO0_WPRTN,   SDIO, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(27, SDIO0_DETN,    SDIO, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(28, SDIO1_WPRTN,   SDIO, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(29, SDIO1_DETN,    SDIO, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(30, GPIO2_30,      GPIO, MAC1, ____, ____, ____, ____, 0),
	TH1520_PAD(31, GPIO2_31,      GPIO, MAC1, ____, ____, ____, ____, 0),
	TH1520_PAD(32, GPIO3_0,       GPIO, MAC1, ____, ____, ____, ____, 0),
	TH1520_PAD(33, GPIO3_1,       GPIO, MAC1, ____, ____, ____, ____, 0),
	TH1520_PAD(34, GPIO3_2,       GPIO, PWM,  ____, ____, ____, ____, 0),
	TH1520_PAD(35, GPIO3_3,       GPIO, PWM,  ____, ____, ____, ____, 0),
	TH1520_PAD(36, HDMI_SCL,      HDMI, PWM,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(37, HDMI_SDA,      HDMI, PWM,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(38, HDMI_CEC,      HDMI, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(39, GMAC0_TX_CLK,  MAC0, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(40, GMAC0_RX_CLK,  MAC0, ____, ____, GPIO, ____, ____, 0),
	TH1520_PAD(41, GMAC0_TXEN,    MAC0, UART, ____, GPIO, ____, ____, 0),
	TH1520_PAD(42, GMAC0_TXD0,    MAC0, UART, ____, GPIO, ____, ____, 0),
	TH1520_PAD(43, GMAC0_TXD1,    MAC0, UART, ____, GPIO, ____, ____, 0),
	TH1520_PAD(44, GMAC0_TXD2,    MAC0, UART, ____, GPIO, ____, ____, 0),
	TH1520_PAD(45, GMAC0_TXD3,    MAC0, I2C,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(46, GMAC0_RXDV,    MAC0, I2C,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(47, GMAC0_RXD0,    MAC0, I2C,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(48, GMAC0_RXD1,    MAC0, I2C,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(49, GMAC0_RXD2,    MAC0, SPI,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(50, GMAC0_RXD3,    MAC0, SPI,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(51, GMAC0_MDC,     MAC0, SPI,  MAC1, GPIO, ____, ____, 0),
	TH1520_PAD(52, GMAC0_MDIO,    MAC0, SPI,  MAC1, GPIO, ____, ____, 0),
	TH1520_PAD(53, GMAC0_COL,     MAC0, PWM,  ____, GPIO, ____, ____, 0),
	TH1520_PAD(54, GMAC0_CRS,     MAC0, PWM,  ____, GPIO, ____, ____, 0),
};

static const struct pinctrl_pin_desc th1520_group4_pins[] = {
	TH1520_PAD(0,  PA0_FUNC,  AUD_VAD,  AUD_VAD_PDM, AUD_SPDIF0, AUD_I2S_8CH, ____, ____, 0),
	TH1520_PAD(1,  PA1_FUNC,  AUD_VAD,  AUD_VAD_PDM, AUD_SPDIF0, AUD_I2S_8CH, ____, ____, 0),
	TH1520_PAD(2,  PA2_FUNC,  AUD_VAD,  ____,        AUD_SPDIF1, AUD_I2S_8CH, ____, ____, 0),
	TH1520_PAD(3,  PA3_FUNC,  AUD_VAD,  AUD_VAD_PDM, AUD_SPDIF1, AUD_I2S_8CH, ____, ____, 0),
	TH1520_PAD(4,  PA4_FUNC,  AUD_VAD,  AUD_VAD_PDM, ____,       AUD_I2S_8CH, ____, ____, 0),
	TH1520_PAD(5,  PA5_FUNC,  AUD_VAD,  AUD_VAD_PDM, ____,       AUD_I2S_8CH, ____, ____, 0),
	TH1520_PAD(6,  PA6_FUNC,  AUD_I2C0, ____,        AUD_I2C1,   ____,        ____, ____, 0),
	TH1520_PAD(7,  PA7_FUNC,  AUD_I2C0, ____,        AUD_I2C1,   ____,        ____, ____, 0),
	TH1520_PAD(8,  PA8_FUNC,  ____,     ____,        AUD_VAD,    AUD_I2S_8CH, ____, ____, 0),
	TH1520_PAD(9,  PA9_FUNC,  AUD_I2S0, ____,        AUD_TDM,    AUD_I2S1,    ____, ____, 0),
	TH1520_PAD(10, PA10_FUNC, AUD_I2S0, ____,        AUD_TDM,    AUD_I2S1,    ____, ____, 0),
	TH1520_PAD(11, PA11_FUNC, AUD_I2S0, ____,        AUD_TDM,    AUD_I2S1,    ____, ____, 0),
	TH1520_PAD(12, PA12_FUNC, AUD_I2S0, AUD_I2C1,    ____,       AUD_I2S1,    ____, ____, 0),
	TH1520_PAD(13, PA13_FUNC, AUD_I2S1, AUD_I2C1,    AUD_VAD,    ____,        ____, ____, 0),
	TH1520_PAD(14, PA14_FUNC, AUD_I2S1, AUD_VAD_PDM, AUD_VAD,    AUD_I2S0,    ____, ____, 0),
	TH1520_PAD(15, PA15_FUNC, AUD_I2S1, AUD_VAD_PDM, AUD_VAD,    ____,        ____, ____, 0),
	TH1520_PAD(16, PA16_FUNC, AUD_I2S1, AUD_VAD_PDM, AUD_VAD,    AUD_I2C1,    ____, ____, 0),
	TH1520_PAD(17, PA17_FUNC, AUD_I2S1, AUD_VAD_PDM, AUD_VAD,    AUD_I2C1,    ____, ____, 0),
	TH1520_PAD(18, PA18_FUNC, AUD_I2S2, AUD_TDM,     AUD_VAD,    ____,        ____, ____, 0),
	TH1520_PAD(19, PA19_FUNC, AUD_I2S2, AUD_TDM,     AUD_VAD,    ____,        ____, ____, 0),
	TH1520_PAD(20, PA20_FUNC, AUD_I2S2, AUD_TDM,     AUD_I2C1,   ____,        ____, ____, 0),
	TH1520_PAD(21, PA21_FUNC, AUD_I2S2, AUD_SPDIF0,  AUD_I2C1,   ____,        ____, ____, 0),
	TH1520_PAD(22, PA22_FUNC, AUD_I2S2, AUD_SPDIF0,  ____,       ____,        ____, ____, 0),
	TH1520_PAD(23, PA23_FUNC, ____,     AUD_SPDIF1,  AUD_SPDIF0, ____,        ____, ____, 0),
	TH1520_PAD(24, PA24_FUNC, ____,     AUD_SPDIF1,  AUD_SPDIF0, AUD_I2S_8CH, ____, ____, 0),
	TH1520_PAD(25, PA25_FUNC, AUD_I2S_8CH, ____,     AUD_SPDIF0, AUD_I2C1,    ____, ____, 0),
	TH1520_PAD(26, PA26_FUNC, AUD_I2S_8CH, ____,     AUD_SPDIF0, AUD_I2C1,    ____, ____, 0),
	TH1520_PAD(27, PA27_FUNC, AUD_I2S_8CH, AUD_TDM,  AUD_SPDIF1, AUD_I2S0,    ____, ____, 0),
	TH1520_PAD(28, PA28_FUNC, AUD_I2S_8CH, AUD_TDM,  AUD_SPDIF1, AUD_I2S0,    ____, ____, 0),
	TH1520_PAD(29, PA29_FUNC, AUD_I2S_8CH, AUD_TDM,  AUD_I2C0,   AUD_I2S0,    ____, ____, 0),
	TH1520_PAD(30, PA30_FUNC, AUD_I2S_8CH, ____,     AUD_I2C0,   AUD_I2S0,    ____, ____, 0),
};

static const struct th1520_pad_group th1520_group1 = {
	.name = "th1520-group1",
	.pins = th1520_group1_pins,
	.npins = ARRAY_SIZE(th1520_group1_pins),
	.offset_mux = 0x400,
	.mask_mux = 0xf,
	.offset_cfg = 0x0,
	.mask_cfg = 0xffff,
	.type = TH1520_PADCTRL_AON,
	.custom_ops = NULL,
};

static const struct th1520_pad_group th1520_group2 = {
	.name = "th1520-group2",
	.pins = th1520_group2_pins,
	.npins = ARRAY_SIZE(th1520_group2_pins),
	.offset_mux = 0x400,
	.mask_mux = 0xf,
	.offset_cfg = 0x0,
	.mask_cfg = 0xffff,
	.type = TH1520_PADCTRL_1,
	.custom_ops = NULL,
};

static const struct th1520_pad_group th1520_group3 = {
	.name = "th1520-group3",
	.pins = th1520_group3_pins,
	.npins = ARRAY_SIZE(th1520_group3_pins),
	.offset_mux = 0x400,
	.mask_mux = 0xf,
	.offset_cfg = 0x0,
	.mask_cfg = 0xffff,
	.type = TH1520_PADCTRL_0,
	.custom_ops = NULL,
};

static const struct th1520_pad_group th1520_group4 = {
	.name = "th1520-group4",
	.pins = th1520_group4_pins,
	.npins = ARRAY_SIZE(th1520_group4_pins),
	.offset_mux = 0x4,
	.mask_mux = 0x3,
	.offset_cfg = 0xc,
	.mask_cfg = 0xffff,
	.type = TH1520_PADCTRL_AUDIO,
	.custom_ops = &th1520_custom_ops,
};

static int th1520_pinctrl_get_groups_count(struct pinctrl_dev *pctldev)
{
	struct th1520_pinctrl *thp = pinctrl_dev_get_drvdata(pctldev);

	return thp->desc.npins;
}

static const char *th1520_pinctrl_get_group_name(struct pinctrl_dev *pctldev,
						 unsigned int gsel)
{
	struct th1520_pinctrl *thp = pinctrl_dev_get_drvdata(pctldev);

	return thp->desc.pins[gsel].name;
}

static int th1520_pinctrl_get_group_pins(struct pinctrl_dev *pctldev,
					 unsigned int gsel,
					 const unsigned int **pins,
					 unsigned int *npins)
{
	struct th1520_pinctrl *thp = pinctrl_dev_get_drvdata(pctldev);

	*pins = &thp->desc.pins[gsel].number;
	*npins = 1;
	return 0;
}

#ifdef CONFIG_DEBUG_FS
static void th1520_pin_dbg_show(struct pinctrl_dev *pctldev,
				struct seq_file *s, unsigned int pin)
{
	struct th1520_pinctrl *thp = pinctrl_dev_get_drvdata(pctldev);
	void __iomem *padcfg = th1520_padcfg(thp, pin);
	void __iomem *muxcfg = th1520_muxcfg(thp, pin);
	u32 pad;
	u32 mux;

	scoped_guard(raw_spinlock_irqsave, &thp->lock) {
		pad = readl_relaxed(padcfg);
		mux = readl_relaxed(muxcfg);
	}

	seq_printf(s, "[PADCFG_%03u:0x%x=0x%07x MUXCFG_%03u:0x%x=0x%08x]",
		   1 + pin / 2, 0x000 + 4 * (pin / 2), pad,
		   1 + pin / 8, 0x400 + 4 * (pin / 8), mux);
}
#else
#define th1520_pin_dbg_show NULL
#endif

static void th1520_pinctrl_dt_free_map(struct pinctrl_dev *pctldev,
				       struct pinctrl_map *map, unsigned int nmaps)
{
	unsigned long *seen = NULL;
	unsigned int i;

	for (i = 0; i < nmaps; i++) {
		if (map[i].type == PIN_MAP_TYPE_CONFIGS_PIN &&
		    map[i].data.configs.configs != seen) {
			seen = map[i].data.configs.configs;
			kfree(seen);
		}
	}

	kfree(map);
}

static int th1520_pinctrl_dt_node_to_map(struct pinctrl_dev *pctldev,
					 struct device_node *np,
					 struct pinctrl_map **maps,
					 unsigned int *num_maps)
{
	struct th1520_pinctrl *thp = pinctrl_dev_get_drvdata(pctldev);
	struct device_node *child;
	struct pinctrl_map *map;
	unsigned long *configs;
	unsigned int nconfigs;
	unsigned int nmaps;
	int ret;

	nmaps = 0;
	for_each_available_child_of_node(np, child) {
		int npins = of_property_count_strings(child, "pins");

		if (npins <= 0) {
			of_node_put(child);
			dev_err(thp->pctl->dev, "no pins selected for %pOFn.%pOFn\n",
				np, child);
			return -EINVAL;
		}
		nmaps += npins;
		if (of_property_present(child, "function"))
			nmaps += npins;
	}

	map = kcalloc(nmaps, sizeof(*map), GFP_KERNEL);
	if (!map)
		return -ENOMEM;

	nmaps = 0;
	mutex_lock(&thp->mutex);
	for_each_available_child_of_node(np, child) {
		unsigned int rollback = nmaps;
		enum th1520_muxtype muxtype;
		struct property *prop;
		const char *funcname;
		const char **pgnames;
		const char *pinname;
		int npins;

		ret = pinconf_generic_parse_dt_config(child, pctldev, &configs, &nconfigs);
		if (ret) {
			dev_err(thp->pctl->dev, "%pOFn.%pOFn: error parsing pin config\n",
				np, child);
			goto put_child;
		}

		if (!of_property_read_string(child, "function", &funcname)) {
			muxtype = th1520_muxtype_get(funcname);
			if (!muxtype) {
				dev_err(thp->pctl->dev, "%pOFn.%pOFn: unknown function '%s'\n",
					np, child, funcname);
				ret = -EINVAL;
				goto free_configs;
			}

			funcname = devm_kasprintf(thp->pctl->dev, GFP_KERNEL, "%pOFn.%pOFn",
						  np, child);
			if (!funcname) {
				ret = -ENOMEM;
				goto free_configs;
			}

			npins = of_property_count_strings(child, "pins");
			pgnames = devm_kcalloc(thp->pctl->dev, npins, sizeof(*pgnames), GFP_KERNEL);
			if (!pgnames) {
				ret = -ENOMEM;
				goto free_configs;
			}
		} else {
			funcname = NULL;
		}

		npins = 0;
		of_property_for_each_string(child, "pins", prop, pinname) {
			unsigned int i;

			for (i = 0; i < thp->desc.npins; i++) {
				if (!strcmp(pinname, thp->desc.pins[i].name))
					break;
			}
			if (i == thp->desc.npins) {
				nmaps = rollback;
				dev_err(thp->pctl->dev, "%pOFn.%pOFn: unknown pin '%s'\n",
					np, child, pinname);
				goto free_configs;
			}

			if (nconfigs) {
				map[nmaps].type = PIN_MAP_TYPE_CONFIGS_PIN;
				map[nmaps].data.configs.group_or_pin = thp->desc.pins[i].name;
				map[nmaps].data.configs.configs = configs;
				map[nmaps].data.configs.num_configs = nconfigs;
				nmaps += 1;
			}
			if (funcname) {
				pgnames[npins++] = thp->desc.pins[i].name;
				map[nmaps].type = PIN_MAP_TYPE_MUX_GROUP;
				map[nmaps].data.mux.function = funcname;
				map[nmaps].data.mux.group = thp->desc.pins[i].name;
				nmaps += 1;
			}
		}

		if (funcname) {
			ret = pinmux_generic_add_function(pctldev, funcname, pgnames,
							  npins, (void *)muxtype);
			if (ret < 0) {
				dev_err(thp->pctl->dev, "error adding function %s\n", funcname);
				goto put_child;
			}
		}
	}

	*maps = map;
	*num_maps = nmaps;
	mutex_unlock(&thp->mutex);
	return 0;

free_configs:
	kfree(configs);
put_child:
	of_node_put(child);
	th1520_pinctrl_dt_free_map(pctldev, map, nmaps);
	mutex_unlock(&thp->mutex);
	return ret;
}

static const struct pinctrl_ops th1520_pinctrl_ops = {
	.get_groups_count = th1520_pinctrl_get_groups_count,
	.get_group_name = th1520_pinctrl_get_group_name,
	.get_group_pins = th1520_pinctrl_get_group_pins,
	.pin_dbg_show = th1520_pin_dbg_show,
	.dt_node_to_map = th1520_pinctrl_dt_node_to_map,
	.dt_free_map = th1520_pinctrl_dt_free_map,
};

static const u8 th1520_drive_strength_in_mA[16] = {
	1, 2, 3, 5, 7, 8, 10, 12, 13, 15, 16, 18, 20, 21, 23, 25,
};

static u16 th1520_drive_strength_from_mA(u32 arg)
{
	u16 ds;

	for (ds = 0; ds < TH1520_PADCFG_DS; ds++) {
		if (arg <= th1520_drive_strength_in_mA[ds])
			return ds;
	}
	return TH1520_PADCFG_DS;
}

static int th1520_padcfg_rmw(struct th1520_pinctrl *thp, unsigned int pin,
			     u32 mask, u32 value)
{
	void __iomem *padcfg = th1520_padcfg(thp, pin);
	unsigned int shift = th1520_padcfg_shift(thp, pin);
	u32 tmp;

	mask <<= shift;
	value <<= shift;

	scoped_guard(raw_spinlock_irqsave, &thp->lock) {
		tmp = readl_relaxed(padcfg);
		tmp = (tmp & ~mask) | value;
		writel_relaxed(tmp, padcfg);
	}
	return 0;
}

static int th1520_pinconf_get(struct pinctrl_dev *pctldev,
			      unsigned int pin, unsigned long *config)
{
	struct th1520_pinctrl *thp = pinctrl_dev_get_drvdata(pctldev);
	const struct pin_desc *desc = pin_desc_get(pctldev, pin);
	bool enabled;
	int param;
	u32 value;
	u32 arg;

	if ((uintptr_t)desc->drv_data & TH1520_PAD_NO_PADCFG)
		return -ENOTSUPP;

	value = readl_relaxed(th1520_padcfg(thp, pin));
	value = (value >> th1520_padcfg_shift(thp, pin)) & GENMASK(9, 0);

	param = pinconf_to_config_param(*config);
	switch (param) {
	case PIN_CONFIG_BIAS_DISABLE:
		enabled = !(value & (TH1520_PADCFG_SPU | TH1520_PADCFG_PE));
		arg = 0;
		break;
	case PIN_CONFIG_BIAS_PULL_DOWN:
		enabled = (value & TH1520_PADCFG_BIAS) == TH1520_PADCFG_PE;
		arg = enabled ? TH1520_PULL_DOWN_OHM : 0;
		break;
	case PIN_CONFIG_BIAS_PULL_UP:
		if (value & TH1520_PADCFG_SPU) {
			enabled = true;
			arg = TH1520_PULL_STRONG_OHM;
		} else if ((value & (TH1520_PADCFG_PE | TH1520_PADCFG_PS)) ==
				    (TH1520_PADCFG_PE | TH1520_PADCFG_PS)) {
			enabled = true;
			arg = TH1520_PULL_UP_OHM;
		} else {
			enabled = false;
			arg = 0;
		}
		break;
	case PIN_CONFIG_DRIVE_STRENGTH:
		enabled = true;
		arg = th1520_drive_strength_in_mA[value & TH1520_PADCFG_DS];
		break;
	case PIN_CONFIG_INPUT_ENABLE:
		enabled = value & TH1520_PADCFG_IE;
		arg = enabled ? 1 : 0;
		break;
	case PIN_CONFIG_INPUT_SCHMITT_ENABLE:
		enabled = value & TH1520_PADCFG_ST;
		arg = enabled ? 1 : 0;
		break;
	case PIN_CONFIG_SLEW_RATE:
		enabled = value & TH1520_PADCFG_SL;
		arg = enabled ? 1 : 0;
		break;
	default:
		return -ENOTSUPP;
	}

	*config = pinconf_to_config_packed(param, arg);
	return enabled ? 0 : -EINVAL;
}

static int th1520_pinconf_group_get(struct pinctrl_dev *pctldev,
				    unsigned int gsel, unsigned long *config)
{
	struct th1520_pinctrl *thp = pinctrl_dev_get_drvdata(pctldev);
	unsigned int pin = thp->desc.pins[gsel].number;

	return th1520_pinconf_get(pctldev, pin, config);
}

static int th1520_pinconf_set(struct pinctrl_dev *pctldev, unsigned int pin,
			      unsigned long *configs, unsigned int num_configs)
{
	struct th1520_pinctrl *thp = pinctrl_dev_get_drvdata(pctldev);
	const struct pin_desc *desc = pin_desc_get(pctldev, pin);
	unsigned int i;
	u16 mask, value;

	if ((uintptr_t)desc->drv_data & TH1520_PAD_NO_PADCFG)
		return -ENOTSUPP;

	mask = 0;
	value = 0;
	for (i = 0; i < num_configs; i++) {
		int param = pinconf_to_config_param(configs[i]);
		u32 arg = pinconf_to_config_argument(configs[i]);

		switch (param) {
		case PIN_CONFIG_BIAS_DISABLE:
			mask |= TH1520_PADCFG_BIAS;
			value &= ~TH1520_PADCFG_BIAS;
			break;
		case PIN_CONFIG_BIAS_PULL_DOWN:
			if (arg == 0)
				return -ENOTSUPP;
			mask |= TH1520_PADCFG_BIAS;
			value &= ~TH1520_PADCFG_BIAS;
			value |= TH1520_PADCFG_PE;
			break;
		case PIN_CONFIG_BIAS_PULL_UP:
			if (arg == 0)
				return -ENOTSUPP;
			mask |= TH1520_PADCFG_BIAS;
			value &= ~TH1520_PADCFG_BIAS;
			if (arg == TH1520_PULL_STRONG_OHM)
				value |= TH1520_PADCFG_SPU;
			else
				value |= TH1520_PADCFG_PE | TH1520_PADCFG_PS;
			break;
		case PIN_CONFIG_DRIVE_STRENGTH:
			mask |= TH1520_PADCFG_DS;
			value &= ~TH1520_PADCFG_DS;
			value |= th1520_drive_strength_from_mA(arg);
			break;
		case PIN_CONFIG_INPUT_ENABLE:
			mask |= TH1520_PADCFG_IE;
			if (arg)
				value |= TH1520_PADCFG_IE;
			else
				value &= ~TH1520_PADCFG_IE;
			break;
		case PIN_CONFIG_INPUT_SCHMITT_ENABLE:
			mask |= TH1520_PADCFG_ST;
			if (arg)
				value |= TH1520_PADCFG_ST;
			else
				value &= ~TH1520_PADCFG_ST;
			break;
		case PIN_CONFIG_SLEW_RATE:
			mask |= TH1520_PADCFG_SL;
			if (arg)
				value |= TH1520_PADCFG_SL;
			else
				value &= ~TH1520_PADCFG_SL;
			break;
		default:
			return -ENOTSUPP;
		}
	}

	return th1520_padcfg_rmw(thp, pin, mask, value);
}

static int th1520_pinconf_group_set(struct pinctrl_dev *pctldev,
				    unsigned int gsel,
				    unsigned long *configs,
				    unsigned int num_configs)
{
	struct th1520_pinctrl *thp = pinctrl_dev_get_drvdata(pctldev);
	unsigned int pin = thp->desc.pins[gsel].number;

	return th1520_pinconf_set(pctldev, pin, configs, num_configs);
}

#ifdef CONFIG_DEBUG_FS
static void th1520_pinconf_dbg_show(struct pinctrl_dev *pctldev,
				    struct seq_file *s, unsigned int pin)
{
	struct th1520_pinctrl *thp = pinctrl_dev_get_drvdata(pctldev);
	u32 value = readl_relaxed(th1520_padcfg(thp, pin));

	value = (value >> th1520_padcfg_shift(thp, pin)) & GENMASK(9, 0);

	seq_printf(s, " [0x%03x]", value);
}
#else
#define th1520_pinconf_dbg_show NULL
#endif

static const struct pinconf_ops th1520_pinconf_ops = {
	.pin_config_get = th1520_pinconf_get,
	.pin_config_group_get = th1520_pinconf_group_get,
	.pin_config_set = th1520_pinconf_set,
	.pin_config_group_set = th1520_pinconf_group_set,
	.pin_config_dbg_show = th1520_pinconf_dbg_show,
	.is_generic = true,
};

static int th1520_pinmux_set(struct th1520_pinctrl *thp, unsigned int pin,
			     unsigned long muxdata, enum th1520_muxtype muxtype)
{
	void __iomem *muxcfg = th1520_muxcfg(thp, pin);
	unsigned int shift = th1520_muxcfg_shift(thp, pin);
	u32 mask, value, tmp;

	if (thp->custom_ops && thp->custom_ops->init) {
		thp->custom_ops->init(thp, pin);
	}

	for (value = 0; muxdata; muxdata >>= 5, value++) {
		if ((muxdata & GENMASK(4, 0)) == muxtype)
			break;
	}
	if (!muxdata) {
		dev_err(thp->pctl->dev, "invalid mux %s for pin %s\n",
			th1520_muxtype_string[muxtype], pin_get_name(thp->pctl, pin));
		return -EINVAL;
	}

	mask = thp->mask_mux << shift;
	value = value << shift;

	scoped_guard(raw_spinlock_irqsave, &thp->lock) {
		tmp = readl_relaxed(muxcfg);
		tmp = (tmp & ~mask) | value;
		writel_relaxed(tmp, muxcfg);
	}
	return 0;
}

static int th1520_pinmux_set_mux(struct pinctrl_dev *pctldev,
				 unsigned int fsel, unsigned int gsel)
{
	struct th1520_pinctrl *thp = pinctrl_dev_get_drvdata(pctldev);
	const struct function_desc *func = pinmux_generic_get_function(pctldev, fsel);

	return th1520_pinmux_set(thp, thp->desc.pins[gsel].number,
				 (uintptr_t)thp->desc.pins[gsel].drv_data & TH1520_PAD_MUXDATA,
				 (uintptr_t)func->data);
}

static int th1520_gpio_request_enable(struct pinctrl_dev *pctldev,
				      struct pinctrl_gpio_range *range,
				      unsigned int offset)
{
	struct th1520_pinctrl *thp = pinctrl_dev_get_drvdata(pctldev);
	const struct pin_desc *desc = pin_desc_get(pctldev, offset);

	return th1520_pinmux_set(thp, offset,
				 (uintptr_t)desc->drv_data & TH1520_PAD_MUXDATA,
				 TH1520_MUX_GPIO);
}

static int th1520_gpio_set_direction(struct pinctrl_dev *pctldev,
				     struct pinctrl_gpio_range *range,
				     unsigned int offset, bool input)
{
	struct th1520_pinctrl *thp = pinctrl_dev_get_drvdata(pctldev);

	return th1520_padcfg_rmw(thp, offset, TH1520_PADCFG_IE,
				 input ? TH1520_PADCFG_IE : 0);
}

static const struct pinmux_ops th1520_pinmux_ops = {
	.get_functions_count = pinmux_generic_get_function_count,
	.get_function_name = pinmux_generic_get_function_name,
	.get_function_groups = pinmux_generic_get_function_groups,
	.set_mux = th1520_pinmux_set_mux,
	.gpio_request_enable = th1520_gpio_request_enable,
	.gpio_set_direction = th1520_gpio_set_direction,
	.strict = true,
};

static int th1520_pinctrl_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	const struct th1520_pad_group *group = device_get_match_data(dev);
	struct th1520_pinctrl *thp;
	struct clk *clk;
	int ret;

	thp = devm_kzalloc(dev, sizeof(*thp), GFP_KERNEL);
	if (!thp)
		return -ENOMEM;

	thp->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(thp->base))
		return PTR_ERR(thp->base);

	thp->desc.name = group->name;
	thp->desc.pins = group->pins;
	thp->desc.npins = group->npins;
	thp->offset_mux = group->offset_mux;
	thp->mask_mux = group->mask_mux;
	thp->offset_cfg = group->offset_cfg;
	thp->mask_cfg = group->mask_cfg;
	thp->custom_ops = group->custom_ops;
	thp->type = group->type;
	thp->desc.pctlops = &th1520_pinctrl_ops;
	thp->desc.pmxops = &th1520_pinmux_ops;
	thp->desc.confops = &th1520_pinconf_ops;
	thp->desc.owner = THIS_MODULE;
	mutex_init(&thp->mutex);
	raw_spin_lock_init(&thp->lock);

	if ((thp->type == TH1520_PADCTRL_0) ||
			(thp->type == TH1520_PADCTRL_1)) {
		thp->clk = devm_clk_get_enabled(dev, "pclk");
		if (IS_ERR(thp->clk))
			return dev_err_probe(dev, PTR_ERR(thp->clk), "error getting clock\n");
	} else {
		thp->clk = devm_clk_get_enabled(dev, NULL);
		if (IS_ERR(thp->clk))
			return dev_err_probe(dev, PTR_ERR(thp->clk), "error getting clock\n");
	}

	platform_set_drvdata(pdev, thp);
	ret = devm_pinctrl_register_and_init(dev, &thp->desc, thp, &thp->pctl);
	if (ret)
		return dev_err_probe(dev, ret, "could not register pinctrl driver\n");

	return pinctrl_enable(thp->pctl);
}

#ifdef CONFIG_PM_SLEEP
static int th1520_pinctrl_backup_regs(struct th1520_pinctrl *thp, unsigned int cfg_reg_nums,
					unsigned int mux_reg_nums)
{
	int i;

	for (i = 0; i < cfg_reg_nums; i++)
		thp->cfg_bak[i] = readl(TH1520_PM_PAD_CFG(i));
	for (i = 0; i < mux_reg_nums; i++)
		thp->mux_bak[i] = readl(TH1520_PM_PAD_MUX(i));

	return 0;
}

static int th1520_pinctrl_restore_regs(struct th1520_pinctrl *thp, unsigned int cfg_reg_nums,
				unsigned int mux_reg_nums)
{
	int i;

	for (i = 0; i < cfg_reg_nums; i++)
		writel(thp->cfg_bak[i], TH1520_PM_PAD_CFG(i));
	for (i = 0; i < mux_reg_nums; i++)
		writel(thp->mux_bak[i], TH1520_PM_PAD_MUX(i));

	return 0;
}

static int th1520_pinctrl_suspend(struct device *dev)
{
	dev_info(dev, "th1520 pinctrl suspend\n");
	struct th1520_pinctrl *thp = dev_get_drvdata(dev);
	int ret = 0;

	switch(thp->type) {
		case TH1520_PADCTRL_0:
			ret = th1520_pinctrl_backup_regs(thp, TH1520_PADCTRL0_CFG_REG_NUMS, TH1520_PADCTRL0_MUX_REG_NUMS);
			clk_disable_unprepare(thp->clk);
			break;
		case TH1520_PADCTRL_1:
			ret = th1520_pinctrl_backup_regs(thp, TH1520_PADCTRL1_CFG_REG_NUMS, TH1520_PADCTRL1_MUX_REG_NUMS);
			clk_disable_unprepare(thp->clk);
			break;
		case TH1520_PADCTRL_AON:
			ret = th1520_pinctrl_backup_regs(thp, TH1520_AON_CFG_REG_NUMS, TH1520_AON_MUX_REG_NUMS);
			break;
		case TH1520_PADCTRL_AUDIO:
			ret = th1520_pinctrl_backup_regs(thp, TH1520_AUDIO_CFG_REG_NUMS, TH1520_AUDIO_MUX_REG_NUMS);
			thp->mux_bak[TH1520_AUDIO_IO_SEL_IDX] = readl(thp->base);
			break;
		default:
			break;
	}

	return ret;
}

static int th1520_pinctrl_resume(struct device *dev)
{
	dev_info(dev, "th1520 pinctrl resume\n");
	struct th1520_pinctrl *thp = dev_get_drvdata(dev);
	int ret = 0;

	switch(thp->type) {
		case TH1520_PADCTRL_0:
			ret = clk_prepare_enable(thp->clk);
			if (ret) {
				dev_err(dev, "could not enable padctrl clk\n");
				return -EINVAL;
			}
			ret = th1520_pinctrl_restore_regs(thp, TH1520_PADCTRL0_CFG_REG_NUMS, TH1520_PADCTRL0_MUX_REG_NUMS);
			break;
		case TH1520_PADCTRL_1:
			ret = clk_prepare_enable(thp->clk);
			if (ret) {
				dev_err(dev, "could not enable padctrl clk\n");
				return -EINVAL;
			}
			ret = th1520_pinctrl_restore_regs(thp, TH1520_PADCTRL1_CFG_REG_NUMS, TH1520_PADCTRL1_MUX_REG_NUMS);
			break;
		case TH1520_PADCTRL_AON:
			ret = th1520_pinctrl_restore_regs(thp, TH1520_AON_CFG_REG_NUMS, TH1520_AON_MUX_REG_NUMS);
			break;
		case TH1520_PADCTRL_AUDIO:
			ret = th1520_pinctrl_restore_regs(thp, TH1520_AUDIO_CFG_REG_NUMS, TH1520_AUDIO_MUX_REG_NUMS);
			writel(thp->mux_bak[TH1520_AUDIO_IO_SEL_IDX], thp->base);
			break;
		default:
			break;
	}

	return ret;
}
#endif	//CONFIG_PM_SLEEP

static const struct dev_pm_ops th1520_pinctrl_dev_pm_ops = {
	SET_LATE_SYSTEM_SLEEP_PM_OPS(th1520_pinctrl_suspend, th1520_pinctrl_resume)
};

static const struct of_device_id th1520_pinctrl_of_match[] = {
	{ .compatible = "thead,th1520-group1-pinctrl", .data = &th1520_group1 },
	{ .compatible = "thead,th1520-group2-pinctrl", .data = &th1520_group2 },
	{ .compatible = "thead,th1520-group3-pinctrl", .data = &th1520_group3 },
	{ .compatible = "thead,th1520-group4-pinctrl", .data = &th1520_group4 },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, th1520_pinctrl_of_match);

static struct platform_driver th1520_pinctrl_driver = {
	.probe = th1520_pinctrl_probe,
	.driver = {
		.name = "pinctrl-th1520",
		.of_match_table = th1520_pinctrl_of_match,
		.pm = &th1520_pinctrl_dev_pm_ops,
	},
};
module_platform_driver(th1520_pinctrl_driver);

MODULE_DESCRIPTION("Pinctrl driver for the XuanTie TH1520 SoC");
MODULE_AUTHOR("Emil Renner Berthing <emil.renner.berthing@canonical.com>");
MODULE_LICENSE("GPL");
