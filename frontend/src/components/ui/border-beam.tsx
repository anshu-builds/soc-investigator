import {
  BorderBeam as RawBorderBeam,
} from 'border-beam'
import type {
  BorderBeamProps,
  BorderBeamSize,
  BorderBeamTheme,
  BorderBeamColorVariant,
} from 'border-beam'

export type {
  BorderBeamProps,
  BorderBeamSize,
  BorderBeamTheme,
  BorderBeamColorVariant,
}

export function BorderBeam({
  size = 'pulse-outside',
  colorVariant = 'sunset',
  theme = 'light',
  strength = 1,
  brightness = 2.8,
  saturation = 2.6,
  hueRange = 220,
  duration = 1.25,
  ...props
}: BorderBeamProps) {
  return (
    <RawBorderBeam
      size={size}
      colorVariant={colorVariant}
      theme={theme}
      strength={strength}
      brightness={brightness}
      saturation={saturation}
      hueRange={hueRange}
      duration={duration}
      {...props}
    />
  )
}

export default BorderBeam
