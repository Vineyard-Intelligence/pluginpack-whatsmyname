# dist/

The runnable bundle (`whatsmyname-pack.js`) is not built yet. The plugin currently ships as a
**built-in** reference plugin inside the Vineyard app (the manifest member uses `entry: "inline"`).
This catalog manifest exists so the pack is listable/installable in the marketplace; remote
execution from this repo lands when the bundle is built and committed here.
