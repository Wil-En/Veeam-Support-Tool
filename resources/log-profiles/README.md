# Log-viewer profile resources

`Veeam-hybrid-notepad-plus.xml` is the user-supplied Notepad++ language definition
used as the initial vocabulary and palette reference for the built-in Veeam log
viewer. The application does not require Notepad++ to use the internal viewer.

The 0.2.1 viewer applies layered rules:

1. generic timestamp, thread, path, IP, GUID and stack-trace tokens;
2. Veeam-common severity and lifecycle terms;
3. sample-backed Veeam Agent for Microsoft Windows fields;
4. best-effort rules for unrecognized Veeam product logs.

Future VBR, plug-in, proxy and repository fixtures can add product-specific rules
without replacing the common layer.
