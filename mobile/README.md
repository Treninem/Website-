# Work Portal mobile

Native Flutter client for Android and iOS. This is not a WebView and does not open the website inside an app. The Flutter UI calls the shared FastAPI backend directly.

## API address

Pass the server URL at build/run time:

`flutter run --dart-define=API_BASE_URL=https://your-domain.example`

Android emulator default is `http://10.0.2.2:8000`.

## Security model

The mobile app uses the same accounts, roles, sessions, invitation registration, username/password changes and owner permissions as the web portal.

## Build

The repository workflow generates the standard Android/iOS platform folders with Flutter tooling, runs static analysis, builds a release APK, and builds iOS with `--no-codesign` for validation.
