Vault development environment vagrant set up

A simple vagrant set up of a single node Hashicorp vault server.

After running "vagrant up" the vault is initialised, unsealed and an app_id and user_id is created.
The app_id and the user_id are echoed out and can be seen in the output of the "vagrant up" command.

```
==> vault: *** app_id: 9bd6c2a0-8993-47aa-a10a-1d89e2870e43 ***
==> vault: --- user_id: b1644fd8-41a4-41ed-92b5-a6f6f627c1fd ---
```
