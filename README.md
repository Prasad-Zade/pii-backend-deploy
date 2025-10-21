# PII Privacy Handler Backend - Render Deployment

## Deployment Steps

1. Push this folder to a GitHub repository
2. Go to [Render Dashboard](https://dashboard.render.com/)
3. Click "New +" and select "Web Service"
4. Connect your GitHub repository
5. Select this folder as the root directory
6. Render will automatically detect the `render.yaml` configuration
7. Click "Create Web Service"

## Environment Variables (Optional)
- `PORT`: Automatically set by Render (default: 10000)

## API Endpoints
- `GET /api/health` - Health check
- `POST /api/sessions` - Create new chat session
- `GET /api/sessions` - Get all sessions
- `POST /api/sessions/{id}/messages` - Process message
- `DELETE /api/sessions/{id}` - Delete session

## After Deployment
Update your Flutter app's API URLs to point to your Render URL:
- Replace `http://10.0.2.2:5000/api` with `https://your-app.onrender.com/api`
