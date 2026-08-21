import {
  Search,
  UserRound,
  Footprints,
  CircleHelp,
  Fingerprint,
  Camera,
  ScanSearch,
} from 'lucide-react'

const iconBlocks = [
  { Icon: UserRound, x: '8%', y: '10%', size: 'w-14 h-14', rotate: '-8deg' },
  { Icon: Search, x: '76%', y: '14%', size: 'w-14 h-14', rotate: '6deg' },
  { Icon: Footprints, x: '18%', y: '44%', size: 'w-12 h-12', rotate: '-12deg' },
  { Icon: CircleHelp, x: '84%', y: '46%', size: 'w-12 h-12', rotate: '9deg' },
  { Icon: Fingerprint, x: '50%', y: '20%', size: 'w-14 h-14', rotate: '5deg' },
  { Icon: Camera, x: '10%', y: '75%', size: 'w-14 h-14', rotate: '-6deg' },
  { Icon: ScanSearch, x: '78%', y: '76%', size: 'w-14 h-14', rotate: '10deg' },
  { Icon: Search, x: '42%', y: '68%', size: 'w-11 h-11', rotate: '-10deg' },
  { Icon: Fingerprint, x: '60%', y: '52%', size: 'w-10 h-10', rotate: '8deg' },
]

export function InvestigationBlocksBackground() {
  return (
    <div aria-hidden="true" className="pointer-events-none absolute inset-0 overflow-hidden">
      {iconBlocks.map(({ Icon, x, y, size, rotate }, index) => (
        <div
          key={`${x}-${y}-${index}`}
          className="absolute rounded-xl border border-black/10 bg-white/30 shadow-sm backdrop-blur-[1px]"
          style={{
            left: x,
            top: y,
            transform: `rotate(${rotate})`,
            animation: `investigationFloat ${13 + (index % 4) * 3}s ease-in-out ${-index}s infinite`,
          }}
        >
          <div className="flex items-center justify-center p-2.5">
            <Icon className={`${size} text-black/30`} strokeWidth={1.8} />
          </div>
        </div>
      ))}
    </div>
  )
}