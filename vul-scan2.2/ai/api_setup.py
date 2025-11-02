"""
User-friendly API key setup with animations.
"""
import os
import time
import google.generativeai as genai
from typing import Optional


class APISetup:
    """Handles user-friendly API key setup with animations."""
    
    def __init__(self):
        self.api_key = None
        self.setup_complete = False
    
    def check_existing_key(self) -> bool:
        """Check if API key already exists in environment."""
        existing_key = os.getenv("GOOGLE_API_KEY")
        if existing_key and self._validate_key(existing_key):
            self.api_key = existing_key
            self.setup_complete = True
            print(f"✅ Using existing Google API key: {existing_key[:10]}...")
            return True
        return False
    
    def _validate_key(self, key: str) -> bool:
        """Validate if the API key works with a simple test."""
        try:
            # Quick test with minimal setup
            genai.configure(api_key=key)
            
            # Try to list models - this validates the key
            try:
                models = genai.list_models()
                print(f"🔍 API key validated - {len(list(models))} models available")
                return True
            except:
                # If list_models fails, try a simple generation
                model = genai.GenerativeModel('gemini-2.5-flash')
                response = model.generate_content("test", request_options={"timeout": 10})
                return True
                
        except Exception as e:
            print(f"❌ API key validation failed: {e}")
            return False
    
    def _show_animation(self, message: str, duration: int = 2):
        """Show loading animation."""
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        end_time = time.time() + duration
        
        while time.time() < end_time:
            for frame in frames:
                if time.time() >= end_time:
                    break
                print(f"\r{frame} {message}", end="", flush=True)
                time.sleep(0.1)
        print(f"\r✅ {message}")
    
    def setup_api_key(self) -> bool:
        """Interactive API key setup with user."""
        print("\n" + "="*50)
        print("🔐 GOOGLE GEMINI AI SETUP")
        print("="*50)
        
        # Check for existing key first
        if self.check_existing_key():
            return True
        
        print("\nTo use AI analysis, you need a Google Gemini API key.")
        print("It's FREE and takes 2 minutes to get:")
        print("1. Visit: https://aistudio.google.com/app/apikey")
        print("2. Click 'Create API Key'")
        print("3. Copy your key (starts with 'AIza...')")
        print("4. Paste it below\n")
        
        while True:
            try:
                api_key = input("🔑 Enter your Google API key (or 'skip' to continue without AI): ").strip()
                
                if api_key.lower() == 'skip':
                    print("⏭️  Continuing without AI analysis...")
                    return False
                
                if not api_key.startswith('AIza'):
                    print("❌ Invalid key format. Should start with 'AIza'")
                    continue
                
                # Validate the key
                self._show_animation("Validating API key", 3)
                
                if self._validate_key(api_key):
                    self.api_key = api_key
                    self.setup_complete = True
                    
                    # Save to environment for future use
                    os.environ["GOOGLE_API_KEY"] = api_key
                    print("✅ API key validated and saved!")
                    return True
                else:
                    print("❌ Invalid API key. Please check and try again.")
                    print("💡 Make sure:")
                    print("   - You created the key at https://aistudio.google.com/app/apikey")
                    print("   - Your Google account has billing setup (free tier available)")
                    print("   - The 'Generative Language API' is enabled")
                    
            except KeyboardInterrupt:
                print("\n⏹️  Setup cancelled. Continuing without AI...")
                return False
            except Exception as e:
                print(f"❌ Error: {e}. Please try again.")