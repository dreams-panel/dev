# Dreams Panel

![Dreams Panel Logo](logo.png)

> [!WARNING]
> Dont Use DreamsPanel for Production! its still in Development!


Dreams Panel is a Panel for Hostings.
## Features

- **Session Management**: Utilizes Express.js and SQLite for handling user sessions securely.
- **Authentication**: Integrates Passport.js for authentication strategies.
- **Dynamic Routing**: Loads routes dynamically from the 'app' directory.
- **WebSocket Support**: Enhances routes with WebSocket capabilities using express-ws.
- **Addon Management**: Includes an addon manager for extending functionality.
- **Static File Serving**: Configured to serve static files from the 'public' directory.
- **Docker Integrated**: Host your favourite Docker Immages.

## Installation

To run Dreams Panel locally, follow these steps:

1. **Clone Repository**: `git clone https://github.com/dreams-panel/panel.git`
2. **Navigate to Directory**: `cd panel`
3. **Install Dependencies**: `npm install`
4. **Set Up Configuration**: Modify `config.json` with your settings.
5. **Run the Application**: `npm start`
6. **Access the Application**: Open your browser and go to `http://localhost:PORT` (replace PORT with your configured port number).

## Configuration

Modify `config.json` to customize the application settings, including port number, session secret, and other parameters relevant to your deployment environment.

Example `config.json`:
```json
{
    "port": 80,
    "paneldomain": "localhost",
    "panelurl": "http://localhost",
    "version": "1.0.0"
}
