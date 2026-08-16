# Quick Fix for Network Error

## Problem
The upload endpoint `/api/evidence/upload` returns "Network Error" because the backend needs to be restarted to load the new controller.

## Solution

### Step 1: Stop the current backend
Press `Ctrl+C` in the terminal where the backend is running

### Step 2: Restart the backend
```bash
cd backend
mvn spring-boot:run
```

### Step 3: Verify the endpoint is loaded
Look for this in the backend logs:
```
Mapped "{[/evidence/upload],methods=[POST]}" onto ...
```

### Step 4: Test the upload again
- Go back to the frontend
- Try uploading the forensic image again
- Should work now

## Alternative: Hot Reload (if configured)
If you have Spring Boot DevTools:
```bash
cd backend
mvn clean package
# Backend should auto-restart
```

## Verification
After restart, you can test the endpoint manually:
```bash
curl -X POST http://localhost:8081/api/evidence/upload \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -F "caseId=TEST" \
  -F "evidenceFiles=@test.dd"
```

Expected: Should NOT return "Network Error" (even if it fails auth/validation, connection should work)

## If Still Failing

Check backend logs for:
1. Port 8081 in use?
2. Controller not loaded?
3. Compilation errors?

Run:
```bash
cd backend
mvn clean compile
# Look for errors
```
