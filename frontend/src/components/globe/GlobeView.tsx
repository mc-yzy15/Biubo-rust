import { useEffect, useRef } from 'react'
import type { AttackData, AttackNode } from '../../hooks/useGlobeData'

interface GlobeViewProps {
  attackData: AttackData[]
  serverNode: AttackNode
  autoRotate: boolean
  speed: number
  paused: boolean
  globeRef: React.MutableRefObject<any>
  pushAttack: (attack: AttackData) => void
  getGeo: (log: any) => Promise<{ lat: number; lng: number; flag: string }>
  logToAttack: (log: any, server: AttackNode) => Promise<AttackData>
}

export function GlobeView({ attackData, autoRotate, speed, globeRef }: GlobeViewProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const globeInstanceRef = useRef<any>(null)
  const resizeObserverRef = useRef<ResizeObserver | null>(null)

  useEffect(() => {
    if (!containerRef.current) return

    if (globeInstanceRef.current) {
      return
    }

    const Globe = (window as any).Globe
    if (!Globe) {
      console.warn('globe.gl library not loaded')
      return
    }

    globeInstanceRef.current = Globe()(containerRef.current)
      .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-blue-marble.jpg')
      .bumpImageUrl('https://unpkg.com/three-globe/example/img/earth-topology.png')
      .backgroundImageUrl('https://unpkg.com/three-globe/example/img/night-sky.png')
      .width(containerRef.current.offsetWidth)
      .height(containerRef.current.offsetHeight)
      .arcsData([])
      .arcStartLat((d: any) => d.attacker.lat)
      .arcStartLng((d: any) => d.attacker.lng)
      .arcEndLat((d: any) => d.server.lat)
      .arcEndLng((d: any) => d.server.lng)
      .arcColor((d: any) => [d._sc, d._dc])
      .arcAltitudeAutoScale(0.35)
      .arcStroke((d: any) => d.sev * 0.35 + 0.25)
      .arcDashLength(0.4)
      .arcDashGap(0.6)
      .arcDashAnimateTime((d: any) => 2800 - d.sev * 400)
      .arcsTransitionDuration(0)
      .pointsData([])
      .pointLat((d: any) => d.lat)
      .pointLng((d: any) => d.lng)
      .pointColor((d: any) => d.color)
      .pointAltitude(0.01)
      .pointRadius((d: any) => d.r)
      .pointsMerge(false)
      .ringsData([])
      .ringLat((d: any) => d.lat)
      .ringLng((d: any) => d.lng)
      .ringColor((d: any) => (t: number) => `rgba(${d.r},${d.g},${d.b},${Math.max(0, 0.8 - t)})`)
      .ringMaxRadius(4)
      .ringPropagationSpeed(3)
      .ringRepeatPeriod(900)

    const ctrl = globeInstanceRef.current.controls()
    ctrl.autoRotate = true
    ctrl.autoRotateSpeed = 0.35
    ctrl.enableDamping = true
    ctrl.dampingFactor = 0.08
    ctrl.minDistance = 180
    ctrl.maxDistance = 800

    globeRef.current = globeInstanceRef.current

    resizeObserverRef.current = new ResizeObserver(() => {
      if (containerRef.current && globeInstanceRef.current) {
        globeInstanceRef.current.width(containerRef.current.offsetWidth).height(containerRef.current.offsetHeight)
      }
    })
    resizeObserverRef.current.observe(containerRef.current)

    return () => {
      if (resizeObserverRef.current) {
        resizeObserverRef.current.disconnect()
      }
      if (globeInstanceRef.current && globeInstanceRef.current.$destroy) {
        globeInstanceRef.current.$destroy()
      }
      globeInstanceRef.current = null
      globeRef.current = null
    }
  }, [globeRef])

  useEffect(() => {
    if (!globeInstanceRef.current) return

    const now = Date.now()
    const activeData = attackData.filter(d => (now - (d.addedAt || d.timestamp)) < d._ttl)

    const pts: any[] = []
    const rings: any[] = []

    activeData.forEach(d => {
      pts.push({ lat: d.attacker.lat, lng: d.attacker.lng, color: '#ff3a3a', r: 0.25 + d.sev * 0.12 })
      pts.push({ lat: d.server.lat, lng: d.server.lng, color: '#00c8ff', r: 0.2 + d.sev * 0.08 })
      if (now - (d.addedAt || d.timestamp) < 2000) {
        rings.push({ lat: d.attacker.lat, lng: d.attacker.lng, r: 255, g: 58, b: 58 })
        rings.push({ lat: d.server.lat, lng: d.server.lng, r: 0, g: 200, b: 255 })
      }
    })

    globeInstanceRef.current.arcsData([...activeData]).pointsData(pts).ringsData(rings)
  }, [attackData])

  useEffect(() => {
    if (globeInstanceRef.current) {
      globeInstanceRef.current.controls().autoRotate = autoRotate
    }
  }, [autoRotate])

  useEffect(() => {
    if (globeInstanceRef.current) {
      globeInstanceRef.current.controls().autoRotateSpeed = 0.35 * speed
    }
  }, [speed])

  return (
    <div
      ref={containerRef}
      className="globe-container"
    />
  )
}
