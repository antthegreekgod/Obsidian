- **tags:** #linux #privesc #capabilities 
- ------------------------
# Discovery
```shell
getcap -r / 2>/dev/null
```
**Risky capabilities:**
- `cap_setuid+ep
![[capabilities.png]]
- [More Dangerous Capabilities](https://gtfobins.github.io#+capabilities)