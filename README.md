# CyberShield-AI

CyberShield-AI is a multi-modal threat analysis workspace with a React dashboard and a FastAPI service.

## Run locally

1. Configure `backend/.env` with the database URL and JWT secret shown in the root `.env.example`.
2. Start the API from `backend` with the project's Python environment: `python run.py`.
3. Copy `frontend/.env.example` to `frontend/.env`. Set `VITE_API_URL` to the FastAPI origin (default `http://127.0.0.1:8000`).
4. From `frontend`, run `npm install` and `npm run dev`.
5. Open the Vite URL shown in the terminal, create an account, then use the dashboard.

The frontend uses bearer JWT authentication and the existing API routes for authentication/profile, health checks, URL/SMS/email analysis, dashboard overview, unified history, threat indicators, and correlations. Local frontend origins are allowed by default. For another frontend origin, add it to the comma-separated `CORS_ORIGINS` value in `backend/.env`.

## Integration status

- URL, SMS, and email analysis are connected to the current FastAPI endpoints.
- URL forest inference reads the saved tree arrays and evaluates them in Python, so serving URL scans does not import the Windows-blocked scikit-learn native tree extensions. The backend still needs `joblib` and `numpy` to read the existing artifact.
- QR, APK, and network analysis are shown as unavailable because their backend routes are still placeholders.
- The project checklist records 75% agreement between live URL-extractor values and the training dataset, and says final model integration should wait until feature definitions are aligned. The UI displays the result from the existing URL endpoint; validate this model path before relying on it for real-world decisions.
