# framework-bbox-firewall

Simple Python project to manage Bbox firewall rules.

## Features

- List firewall rules
- Ban an IP (add a drop rule)
- Unban by rule ID or source IP
- Optional Flask API with JWT auth

## Requirements

- Python 3.10+
- Admin access to your Bbox

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

Create a `.env` file (or edit existing one):

```env
API_HOST=0.0.0.0
API_PORT=5000
DEBUG=false

APP_USERNAME=admin
APP_PASSWORD=change-me
JWT_SECRET=change-me
JWT_EXP_MINUTES=5

BBOX_HOST=https://mabbox.bytel.fr
BBOX_PASSWORD=your_bbox_password
BBOX_VERIFY_SSL=false
```

## CLI Usage

### List rules

```bash
python main.py --password "YOUR_BBOX_PASSWORD"
```

### Ban an IP

```bash
python add.py --password "YOUR_BBOX_PASSWORD" --srcip 1.2.3.4 --description "ban-temp"
```

### Unban

By ID:

```bash
python delete.py --password "YOUR_BBOX_PASSWORD" --id 1234
```

By source IP:

```bash
python delete.py --password "YOUR_BBOX_PASSWORD" --srcip 1.2.3.4
```

## API Usage (optional)

Start server:

```bash
python app.py
```

Main endpoints:

- `GET /health`
- `POST /login`
- `GET /rules` (auth required)
- `POST /ban` (auth required)
- `POST /unban` (auth required)
- `DELETE /delete-rule/<id>` (auth required)

Use header:

```text
Authorization: Bearer <token>
```
