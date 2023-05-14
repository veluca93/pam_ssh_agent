# pam_ssh_agent
Authenticate `sudo` with a ssh-agent.

Compile this crate, copy `libpam_ssh_agent.so` to `/usr/lib/security`, add the
following line to `/etc/pam.d/sudo`:
```
auth    sufficient  libpam_ssh_agent.so PATH_TO_AUTHORIZED_KEYS
```

and add
```
Defaults env_keep += "SSH_AUTH_SOCK"
```

to `/etc/sudoers`
