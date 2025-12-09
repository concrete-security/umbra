"use client"

import type { ReactNode } from "react"
import { useEffect, useRef, useState } from "react"
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
  const [isReady, setIsReady] = useState(false)
  const previousTheme = useRef<string | null>(null)

  useEffect(() => {
    if (isReady || !resolvedTheme || previousTheme.current) {
      return
    }

    previousTheme.current = resolvedTheme
    setIsReady(true)
  }, [isReady, resolvedTheme])

  useEffect(() => {
    if (!isReady) {
      return
    }

    if (previousTheme.current !== "light") {
      setTheme("light")
    }
  }, [isReady, setTheme])

  useEffect(() => {
    if (!isReady || !resolvedTheme || resolvedTheme === "light") {
      return
    }

    setTheme("light")
  }, [isReady, resolvedTheme, setTheme])

  useEffect(() => {
    if (!isReady) {
      return
    }

    return () => {
      if (previousTheme.current && previousTheme.current !== "light") {
        setTheme(previousTheme.current)
      }
    }
  }, [isReady, setTheme])

  return <>{children}</>
}
