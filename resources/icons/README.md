# Application icon

The Alpha application icon is intentionally simple: a green beveled tile with
`SAT` lettering.

Files:

- `SupportAssistTool.svg` — editable vector source.
- `SupportAssistTool.png` — large preview/source raster.
- `SupportAssistTool.ico` — multi-resolution Windows application resource used
  by the build.

To replace the icon without changing code, overwrite
`SupportAssistTool.ico` with another valid multi-resolution Windows icon and
rebuild. Keep the same filename. Updating the SVG and PNG at the same time is
recommended so documentation and future icon generation remain consistent.

The `.ico` currently contains 16, 20, 24, 32, 40, 48, 64, 128 and 256 pixel
images. Confirm the icon in the title bar, taskbar, Explorer, file properties,
and high-DPI display modes before release.
