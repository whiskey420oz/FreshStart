# Vector Autostart (VM automation)

Use this when you want Vector to start automatically on the Ubuntu VM.

## 1) Ensure config exists

```
/opt/freshstart/vector/vector.toml
```

## 2) Install systemd service

Copy the service unit from this repo to the VM:

```
sudo cp /path/to/FreshStart/vector/vector.service /etc/systemd/system/vector-freshstart.service
```

Then enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable vector-freshstart
sudo systemctl start vector-freshstart
```

## 3) Check status

```bash
sudo systemctl status vector-freshstart
```

## 4) Logs

```bash
sudo journalctl -u vector-freshstart -f
```

## Notes
- Vector will own UDP 1515 (or whatever port you configured).
- Run FreshStart with `USE_VECTOR=true` so the syslog listener is skipped.
