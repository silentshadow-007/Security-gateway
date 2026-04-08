from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Presidio import 
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

app = FastAPI(title="AI Security Guard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Presidio setup
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

class MessageRequest(BaseModel):
    message: str

@app.post("/secure")
async def secure_gateway(request: MessageRequest):
    user_message = request.message.strip()
    
    if not user_message:
        raise HTTPException(status_code=400, detail="Message can not be empty")

    # Step 1: PII Personal Info
    results = analyzer.analyze(text=user_message, language="en")
    anonymized_text = anonymizer.anonymize(text=user_message, analyzer_results=results).text

    # Step 2: Simple Injection / Jailbreak check 
    dangerous_keywords = [
        "ignore previous instructions", "ignore all previous", 
        "you are now", "forget all rules", "jailbreak", 
        "dan mode", "developer mode", "system prompt", 
        "reveal your instructions", "disregard"
    ]
    
    is_injection = any(keyword.lower() in user_message.lower() for keyword in dangerous_keywords)
    
    # Decide Policy
    if is_injection:
        return {
            "status": "BLOCKED",
            "reason": "Prompt Injection / Jailbreak attempt detected",
            "original_message": user_message,
            "final_message": None
        }
    
    elif results:  # If PII run then this code executes
        return {
            "status": "MASKED",
            "reason": "Personal information masked",
            "original_message": user_message,
            "final_message": anonymized_text
        }
    
    else:
        return {
            "status": "ALLOWED",
            "reason": "Message safe hai",
            "original_message": user_message,
            "final_message": user_message
        }

# Server run 
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)