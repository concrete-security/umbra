"use client"

import type { ReactNode } from "react"
import { useEffect, useRef } from "react"
import { useTheme } from "next-themes"

type ForceLightThemeProps = {
  children?: ReactNode
}

/**
 * Locks the global theme to light while this component is mounted.
 * Used for marketing surfaces that should not inherit dark styling.
 */
export function ForceLightTheme({ children }: ForceLightThemeProps) {
  const { setTheme, resolvedTheme } = useTheme()
  const previousTheme = useRef<string | undefined>(undefined)
  const hasForcedRef = useRef(false)

  useEffect(() => {
    if (!hasForcedRef.current && resolvedTheme) {
      previousTheme.current = resolvedTheme
      hasForcedRef.current = true
    }
  }, [resolvedTheme])

  useEffect(() => {
    setTheme("light")
  }, [])

  useEffect(() => {
    if (resolvedTheme && resolvedTheme !== "light") {
      setTheme("light")
    }
  }, [resolvedTheme, setTheme])

  useEffect(() => {
    return () => {
      if (previousTheme.current && previousTheme.current !== "light") {
        setTheme(previousTheme.current)
      }
    }
  }, [setTheme])

  return <>{children}</>
}
