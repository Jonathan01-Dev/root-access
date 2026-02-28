# Demo Steps (Jury)

## 1) Start node A

```powershell
cd Archipel_Team\src
python main.py start --port 7777 --identity-file idA.key --peer-db peer_table_A.json --no-ai
```

## 2) Start node B

```powershell
cd Archipel_Team\src
python main.py start --port 7778 --identity-file idB.key --peer-db peer_table_B.json --no-ai
```

## 3) Verify discovery

On both nodes:

```text
peers
```

## 4) Send encrypted message

From node A:

```text
msg <node_b_id> Hello secure local mesh
```

## 5) Transfer file

From node A:

```text
send <node_b_id> C:\path\to\file.bin
```

On node B:

```text
receive
download <file_id>
status
```

