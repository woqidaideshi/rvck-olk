/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright(c) 2013-2015 Intel Corporation. All rights reserved.
 */
#ifndef __LINUX_ND_H__
#define __LINUX_ND_H__
#include <linux/fs.h>
#include <linux/ndctl.h>
#include <linux/device.h>
#include <linux/badblocks.h>
#include <linux/perf_event.h>
#include <linux/kabi.h>

enum nvdimm_event {
	NVDIMM_REVALIDATE_POISON,
	NVDIMM_REVALIDATE_REGION,
};

enum nvdimm_claim_class {
	NVDIMM_CCLASS_NONE,
	NVDIMM_CCLASS_BTT,
	NVDIMM_CCLASS_BTT2,
	NVDIMM_CCLASS_PFN,
	NVDIMM_CCLASS_DAX,
	NVDIMM_CCLASS_UNKNOWN,
};

#define NVDIMM_EVENT_VAR(_id)  event_attr_##_id
#define NVDIMM_EVENT_PTR(_id)  (&event_attr_##_id.attr.attr)

#define NVDIMM_EVENT_ATTR(_name, _id)				\
	PMU_EVENT_ATTR(_name, NVDIMM_EVENT_VAR(_id), _id,	\
			nvdimm_events_sysfs_show)

/* Event attribute array index */
#define NVDIMM_PMU_FORMAT_ATTR	0
#define NVDIMM_PMU_EVENT_ATTR	1
#define NVDIMM_PMU_CPUMASK_ATTR	2
#define NVDIMM_PMU_NULL_ATTR	3

/**
 * struct nvdimm_pmu - data structure for nvdimm perf driver
 * @pmu: pmu data structure for nvdimm performance stats.
 * @dev: nvdimm device pointer.
 * @cpu: designated cpu for counter access.
 * @node: node for cpu hotplug notifier link.
 * @cpuhp_state: state for cpu hotplug notification.
 * @arch_cpumask: cpumask to get designated cpu for counter access.
 */
struct nvdimm_pmu {
	struct pmu pmu;
	struct device *dev;
	int cpu;
	struct hlist_node node;
	enum cpuhp_state cpuhp_state;
	/* cpumask provided by arch/platform specific code */
	struct cpumask arch_cpumask;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
	KABI_RESERVE(5)
};

struct platform_device;

#ifdef CONFIG_PERF_EVENTS
extern ssize_t nvdimm_events_sysfs_show(struct device *dev,
					struct device_attribute *attr,
					char *page);

int register_nvdimm_pmu(struct nvdimm_pmu *nvdimm, struct platform_device *pdev);
void unregister_nvdimm_pmu(struct nvdimm_pmu *nd_pmu);

#else
static inline int register_nvdimm_pmu(struct nvdimm_pmu *nvdimm, struct platform_device *pdev)
{
	return -ENXIO;
}

static inline void unregister_nvdimm_pmu(struct nvdimm_pmu *nd_pmu) { }
#endif

struct nd_device_driver {
	struct device_driver drv;
	unsigned long type;
	int (*probe)(struct device *dev);
	void (*remove)(struct device *dev);
	void (*shutdown)(struct device *dev);
	void (*notify)(struct device *dev, enum nvdimm_event event);

	KABI_RESERVE(1)
	KABI_RESERVE(2)
};

static inline struct nd_device_driver *to_nd_device_driver(
		struct device_driver *drv)
{
	return container_of(drv, struct nd_device_driver, drv);
};

/**
 * struct nd_namespace_common - core infrastructure of a namespace
 * @force_raw: ignore other personalities for the namespace (e.g. btt)
 * @dev: device model node
 * @claim: when set a another personality has taken ownership of the namespace
 * @claim_class: restrict claim type to a given class
 * @rw_bytes: access the raw namespace capacity with byte-aligned transfers
 */
struct nd_namespace_common {
	int force_raw;
	struct device dev;
	struct device *claim;
	enum nvdimm_claim_class claim_class;
	int (*rw_bytes)(struct nd_namespace_common *, resource_size_t offset,
			void *buf, size_t size, int rw, unsigned long flags);
};

static inline struct nd_namespace_common *to_ndns(struct device *dev)
{
	return container_of(dev, struct nd_namespace_common, dev);
}

/**
 * struct nd_namespace_io - device representation of a persistent memory range
 * @dev: namespace device created by the nd region driver
 * @res: struct resource conversion of a NFIT SPA table
 * @size: cached resource_size(@res) for fast path size checks
 * @addr: virtual address to access the namespace range
 * @bb: badblocks list for the namespace range
 */
struct nd_namespace_io {
	struct nd_namespace_common common;
	struct resource res;
	resource_size_t size;
	void *addr;
	struct badblocks bb;
};

/**
 * struct nd_namespace_pmem - namespace device for dimm-backed interleaved memory
 * @nsio: device and system physical address range to drive
 * @lbasize: logical sector size for the namespace in block-device-mode
 * @alt_name: namespace name supplied in the dimm label
 * @uuid: namespace name supplied in the dimm label
 * @id: ida allocated id
 */
struct nd_namespace_pmem {
	struct nd_namespace_io nsio;
	unsigned long lbasize;
	char *alt_name;
	uuid_t *uuid;
	int id;

	KABI_RESERVE(1)
	KABI_RESERVE(2)
};

static inline struct nd_namespace_io *to_nd_namespace_io(const struct device *dev)
{
	return container_of(dev, struct nd_namespace_io, common.dev);
}

static inline struct nd_namespace_pmem *to_nd_namespace_pmem(const struct device *dev)
{
	struct nd_namespace_io *nsio = to_nd_namespace_io(dev);

	return container_of(nsio, struct nd_namespace_pmem, nsio);
}

/**
 * nvdimm_read_bytes() - synchronously read bytes from an nvdimm namespace
 * @ndns: device to read
 * @offset: namespace-relative starting offset
 * @buf: buffer to fill
 * @size: transfer length
 *
 * @buf is up-to-date upon return from this routine.
 */
static inline int nvdimm_read_bytes(struct nd_namespace_common *ndns,
		resource_size_t offset, void *buf, size_t size,
		unsigned long flags)
{
	return ndns->rw_bytes(ndns, offset, buf, size, READ, flags);
}

/**
 * nvdimm_write_bytes() - synchronously write bytes to an nvdimm namespace
 * @ndns: device to write
 * @offset: namespace-relative starting offset
 * @buf: buffer to drain
 * @size: transfer length
 *
 * NVDIMM Namepaces disks do not implement sectors internally.  Depending on
 * the @ndns, the contents of @buf may be in cpu cache, platform buffers,
 * or on backing memory media upon return from this routine.  Flushing
 * to media is handled internal to the @ndns driver, if at all.
 */
static inline int nvdimm_write_bytes(struct nd_namespace_common *ndns,
		resource_size_t offset, void *buf, size_t size,
		unsigned long flags)
{
	return ndns->rw_bytes(ndns, offset, buf, size, WRITE, flags);
}

#define MODULE_ALIAS_ND_DEVICE(type) \
	MODULE_ALIAS("nd:t" __stringify(type) "*")
#define ND_DEVICE_MODALIAS_FMT "nd:t%d"

struct nd_region;
void nvdimm_region_notify(struct nd_region *nd_region, enum nvdimm_event event);
int __must_check __nd_driver_register(struct nd_device_driver *nd_drv,
		struct module *module, const char *mod_name);
static inline void nd_driver_unregister(struct nd_device_driver *drv)
{
	driver_unregister(&drv->drv);
}
#define nd_driver_register(driver) \
	__nd_driver_register(driver, THIS_MODULE, KBUILD_MODNAME)
#define module_nd_driver(driver) \
	module_driver(driver, nd_driver_register, nd_driver_unregister)
#endif /* __LINUX_ND_H__ */
