import { Hono } from 'hono'
import si from 'systeminformation'
import { requireAuth } from '../auth/middleware'

const metrics = new Hono()

metrics.get('/', requireAuth(), async (c) => {
  const [cpuLoad, mem] = await Promise.all([
    si.currentLoad(),
    si.mem(),
  ])

  return c.json({
    cpu_percent: Math.round(cpuLoad.currentLoad * 10) / 10,
    ram_used_mb: Math.round(mem.active / 1024 / 1024),
    ram_total_mb: Math.round(mem.total / 1024 / 1024),
    load_avg: Math.round((cpuLoad.avgLoad ?? 0) * 100) / 100,
  })
})

export { metrics as metricsRoute }
