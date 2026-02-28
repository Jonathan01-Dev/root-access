# Demo Steps (Jury)

## 1) Start node A

```powershell
cd Archipel_Team\src
python main.py start --port 7777 --identity-file idA.key --peer-db peer_table_A.json --ui --ui-port 8080 --no-ai
```

## 2) Start node B

```powershell
cd Archipel_Team\src
python main.py start --port 7778 --identity-file idB.key --peer-db peer_table_B.json --ui --ui-port 8081 --no-ai
```

## 3) Open dashboards

- Node A: `http://127.0.0.1:8080`
- Node B: `http://127.0.0.1:8081`

Use the `Peers` panel to verify discovery.

## 4) Send encrypted message

From Node A dashboard:
- Fill `Peer ID`
- Write message
- Click `Send`

## 5) Transfer file

From Node A dashboard:
- In `File Transfer`, set `Target Peer ID` + file path
- Click `Send Manifest`

From Node B dashboard:
- Copy `file_id` from `Files/Downloads`
- Click `Download`
- Follow progress in `Files/Downloads` and `Status`
