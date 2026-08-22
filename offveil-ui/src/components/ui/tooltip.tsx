"use client"

import * as React from "react"
import { Tooltip as TooltipPrimitive } from "radix-ui"

import { cn } from "@/lib/utils"

const DISMISS_EVENT = "offveil:dismiss-tooltips"

let tooltipsArmed = true

function clearStuckHover() {
  const root = document.documentElement
  root.style.pointerEvents = "none"
  void root.offsetHeight
  root.style.removeProperty("pointer-events")
  if (document.activeElement instanceof HTMLElement) {
    document.activeElement.blur()
  }
}

function armTooltips() {
  tooltipsArmed = true
}

function dismissTooltips() {
  tooltipsArmed = false
  clearStuckHover()
  window.dispatchEvent(new Event(DISMISS_EVENT))
}

function TooltipProvider({
  delayDuration = 0,
  disableHoverableContent = true,
  ...props
}: React.ComponentProps<typeof TooltipPrimitive.Provider>) {
  React.useEffect(() => {
    const onMove = (event: PointerEvent) => {
      if (event.movementX !== 0 || event.movementY !== 0) armTooltips()
    }
    const arm = () => armTooltips()
    const onVisibility = () => {
      if (document.visibilityState !== "visible") dismissTooltips()
    }
    window.addEventListener("pointermove", onMove, true)
    window.addEventListener("pointerdown", arm, true)
    window.addEventListener("keydown", arm)
    window.addEventListener("blur", dismissTooltips)
    document.addEventListener("visibilitychange", onVisibility)
    document.addEventListener("pagehide", dismissTooltips)
    return () => {
      window.removeEventListener("pointermove", onMove, true)
      window.removeEventListener("pointerdown", arm, true)
      window.removeEventListener("keydown", arm)
      window.removeEventListener("blur", dismissTooltips)
      document.removeEventListener("visibilitychange", onVisibility)
      document.removeEventListener("pagehide", dismissTooltips)
    }
  }, [])

  return (
    <TooltipPrimitive.Provider
      data-slot="tooltip-provider"
      delayDuration={delayDuration}
      disableHoverableContent={disableHoverableContent}
      {...props}
    />
  )
}

function Tooltip({
  open: openProp,
  defaultOpen,
  onOpenChange,
  ...props
}: React.ComponentProps<typeof TooltipPrimitive.Root>) {
  const [uncontrolledOpen, setUncontrolledOpen] = React.useState(
    defaultOpen ?? false
  )
  const isControlled = openProp !== undefined
  const open = isControlled ? openProp : uncontrolledOpen
  const onOpenChangeRef = React.useRef(onOpenChange)
  onOpenChangeRef.current = onOpenChange

  const setOpen = React.useCallback(
    (next: boolean) => {
      if (next && !tooltipsArmed) return
      if (!isControlled) setUncontrolledOpen(next)
      onOpenChangeRef.current?.(next)
    },
    [isControlled]
  )

  React.useEffect(() => {
    const close = () => setOpen(false)
    window.addEventListener(DISMISS_EVENT, close)
    return () => window.removeEventListener(DISMISS_EVENT, close)
  }, [setOpen])

  return (
    <TooltipPrimitive.Root
      data-slot="tooltip"
      {...props}
      open={open}
      onOpenChange={setOpen}
    />
  )
}

function TooltipTrigger({
  onPointerMove,
  onFocus,
  ...props
}: React.ComponentProps<typeof TooltipPrimitive.Trigger>) {
  return (
    <TooltipPrimitive.Trigger
      data-slot="tooltip-trigger"
      {...props}
      onPointerMove={(event) => {
        if (!tooltipsArmed) {
          event.preventDefault()
          return
        }
        onPointerMove?.(event)
      }}
      onFocus={(event) => {
        if (!tooltipsArmed) {
          event.preventDefault()
          return
        }
        onFocus?.(event)
      }}
    />
  )
}

function TooltipContent({
  className,
  sideOffset = 0,
  children,
  ...props
}: React.ComponentProps<typeof TooltipPrimitive.Content>) {
  return (
    <TooltipPrimitive.Portal>
      <TooltipPrimitive.Content
        data-slot="tooltip-content"
        sideOffset={sideOffset}
        className={cn(
          "z-50 inline-flex w-fit max-w-xs origin-(--radix-tooltip-content-transform-origin) items-center gap-1.5 rounded-md bg-foreground px-3 py-1.5 text-xs text-background has-data-[slot=kbd]:pr-1.5 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 **:data-[slot=kbd]:relative **:data-[slot=kbd]:isolate **:data-[slot=kbd]:z-50 **:data-[slot=kbd]:rounded-sm data-[state=delayed-open]:animate-in data-[state=delayed-open]:fade-in-0 data-[state=delayed-open]:zoom-in-95 data-open:animate-in data-open:fade-in-0 data-open:zoom-in-95",
          className
        )}
        {...props}
      >
        {children}
        <TooltipPrimitive.Arrow className="z-50 size-2.5 translate-y-[calc(-50%_-_2px)] rotate-45 rounded-[2px] bg-foreground fill-foreground" />
      </TooltipPrimitive.Content>
    </TooltipPrimitive.Portal>
  )
}

export {
  dismissTooltips,
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
}
