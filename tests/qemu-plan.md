# opendirectoryd: QEMU test plan

The host tests (`make -C tests check`) cover the store, the property list
code, the hashing, the API requests, the libinfo and membership answers,
and the kernel identity resolver's answers and its register, answer and
cache-clearing sequence against a fake kernel.
These checks cover what only a running PIE can show: the Mach transport,
Libinfo's ds module, CFOpenDirectory and the consumers. They belong in
pie/image's `tests/qemu-boot.sh`, plan step 9.

## Image

- pietoolchain 0.2.0, with the libxpc transport and Libinfo's ds module,
  init 2, opendirectory, opendirectoryd 1, pam-modules, system-cmds and
  base-files 2.
- base-files' dslocal records: root, daemon, nobody, _sshd, _apt, and the
  groups, written by `tools/dslocal-record`.
- build.sh writes pie's record with a known password and puts pie in admin.
- /etc/rc starts opendirectoryd after notifyd and waits until
  `dscl . -read /Users/root RecordName` answers.

## Checks

1. Start: `pgrep opendirectoryd`; syslog has "serving
   /var/db/dslocal/nodes/Default". The node directories are 0700 root, the
   record files 0600 root. No dot files are left in them.
2. Service names: as pie, checking in any of the three service names fails.
3. dscl as pie:
   - `dscl . -read /Users/pie` shows RecordName, UniqueID 501,
     PrimaryGroupID 20, NFSHomeDirectory, UserShell, GeneratedUID,
     AuthenticationAuthority `;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>`,
     Password `********`, and no ShadowHashData.
   - `dscl . -read /Users/pie ShadowHashData` prints "No such key" and
     exits 1.
   - `dscl . -list /Users UniqueID` lists every record once, sorted.
   - `dscl /Search -read /Users/pie AppleMetaNodeLocation` says
     /Local/Default.
4. dscl as root: `dscl . -read /Users/pie ShadowHashData` prints the data.
   `dscl -plist . -read /Users/pie` is a valid XML property list.
5. Writes refused for pie: `dscl . -create /Users/x` (error 4001),
   `dscl . -passwd /Users/root new` (error 5101),
   `dscl . -create /Users/pie UniqueID 0` (error 4001),
   `dscl . -delete /Groups/admin` (error 4001).
6. passwd as pie: `passwd` with the old and a new password succeeds. Then
   ssh, login and sudo accept the new password and refuse the old one.
   `chkpasswd` accepts the new one.
7. chpass as pie: changing the shell to /bin/sh works; to /tmp/x is
   refused. Changing UniqueID is refused.
8. Back-off: six wrong passwords for pie through `chkpasswd`. The next
   attempt with the right password fails at once; syslog shows "is locked
   for N s". After N seconds the right password works. The account-check
   path in pam reports the lock with BackOffSeconds.
9. Root adds a user: the dscl(1) example. Then `id ann` shows 502 and
   admin, `ls -l` of a file chowned to 502 names ann, ann logs in over
   ssh, and `sudo -l` as ann works. The record has a GeneratedUID.
10. Lookups through the ds module: `id pie`, `groups pie`, with the primary group
    first and admin present, `chmod +a "ann allow read" f` and `ls -le f`
    naming ann, and a group nested with NestedGroups giving membership.
11. No duplicates: a small test program that lists getpwent and getgrent
    names finds each name once, though root is in /etc/passwd and dslocal.
12. Cache: `dscl . -create /Users/ann RealName "New Name"`, then the next
    getpwnam in a running process sees the new name.
13. Unsupported calls: a test program calling ODNodeCustomCall and
    ODNodeCopySupportedRecordTypes gets error 10000 at once, no hang.
14. Crash safety: loop `dscl . -create /Users/ann Comment $i` while
    killing opendirectoryd with SIGKILL and restarting it. Every record
    still parses with `dscl . -read`, and no dot files remain after a
    restart.
15. Daemon down: with opendirectoryd stopped, `id root` still works from
    /etc, and `dscl . -read /Users/root` fails with an error, not a hang.
    After a restart new processes work again.
16. Reboot: all of the above still hold, and the changed passwords stay.
17. Timing, on a Pi 4 once the owner allows it: `time chkpasswd` for a
    right and a wrong password and for an unknown user. QEMU times are not
    representative.

## The kernel's identity resolver

These need a kernel that lets root register as the identity resolver.
Its changelog says so. Earlier PIE kernels refuse
every identitysvc caller. Check 18 shows which kernel is running.

Setup, as root: ann as in check 9, uid 502, with a GeneratedUID. Groups
inner (601, GroupMembership ann, a GeneratedUID) and outer (600, NestedGroups
inner's GeneratedUID). bob, uid 503, in no extra group. For each check, a
file in /tmp owned by root, mode 0600, made fresh with `echo x > f`.

18. Registration: syslog has "registered as the identity resolver" after
    each boot, and no "cannot register". On a kernel that refuses, it has
    "cannot register as the identity resolver: Operation not permitted",
    and checks 1 to 17 still pass.
19. A user ACE grants: `chmod +a "ann allow read" /tmp/acl-ann`. As ann,
    `cat /tmp/acl-ann` prints x. As bob it fails with "Permission denied".
    `ls -le` names ann.
20. A nested group ACE grants: `chmod +a "group:outer allow read"
    /tmp/acl-outer`. As ann, `cat` works. As bob it fails.
21. pie's own ACE grants: `chmod +a "pie allow read" /tmp/acl-pie`. As pie,
    `cat` works.
22. A deny ACE is honoured: `chmod 0644 /tmp/acl-deny` and `chmod +a "ann
    deny read" /tmp/acl-deny`. As ann, `cat` fails. As bob it works.
23. A group deny through nesting: `chmod 0644 /tmp/acl-gdeny` and
    `chmod +a "group:outer deny read" /tmp/acl-gdeny`. As ann, `cat` fails.
24. A changed membership is seen:
    - bob logs in over ssh and keeps the session. `cat /tmp/acl-outer`
      fails.
    - As root, `dscl . -append /Groups/inner GroupMembership bob`.
    - At once, in bob's open session, `cat /tmp/acl-outer` works. The
      kernel asks for the membership, since bob's session does not carry
      the group, and the cache was cleared by the change. This needs the
      login to give the kernel bob's uid for membership checks, as
      initgroups(3) does.
    - As root, `dscl . -delete /Groups/inner GroupMembership bob`. A new
      ssh session for bob fails to `cat /tmp/acl-outer`. The open session
      keeps the groups it logged in with.
25. A GUID change is seen: `dscl . -create /Users/ann GeneratedUID` with a
    new UUID. At once, as ann, `cat /tmp/acl-ann` fails, since the ACE
    names the old GUID. `chmod +a "ann allow read"` again grants it.
26. Restart: `kill opendirectoryd`. Syslog shows a new "registered" line
    within 2 s, from the new process. Checks 19 to 22 still hold, with no
    30 s stall.
27. SIGKILL: `kill -9 opendirectoryd`, then at once, as ann, `cat
    /tmp/acl-ann`. It waits at most until rc's restart, about 1 s, and
    then works. No "kauth external resolver timed out" on the console.
28. Speed: as ann, `time cat /tmp/acl-ann` twice. Both take well under
    0.5 s. With no resolver, each lookup waits 0.5 s.
29. Reboot: checks 18 to 22 hold after a reboot.
