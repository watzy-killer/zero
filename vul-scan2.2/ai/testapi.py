import google.generativeai as genai
import os

def test_api_key():
    # Test 1: Check environment variable
    env_key = os.getenv("GOOGLE_API_KEY")
    print(f"Environment key: {env_key[:10] if env_key else 'None'}...")
    
    # Test 2: Test with your specific key
    test_key = "AIzaSyDaIiT_FHmpOU6IVeLZl2_tRevs45YkCHA"  # Your key
    
    try:
        genai.configure(api_key=test_key)
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content("Say 'API test successful'")
        print("✅ DIRECT KEY TEST: SUCCESS!")
        print(f"Response: {response.text}")
        return True
    except Exception as e:
        print(f"❌ DIRECT KEY TEST FAILED: {e}")
        return False

if __name__ == "__main__":
    test_api_key()