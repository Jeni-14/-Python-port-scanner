import re

print("=" * 60)
print("              PHISHING URL DETECTOR")
print("=" * 60)

url = input("\nEnter URL: ")

risk_score = 0
reasons = []

# HTTP Check
if url.startswith("http://"):
    risk_score += 2
    reasons.append("Uses HTTP instead of HTTPS")

# URL Length Check
if len(url) > 50:
    risk_score += 1
    reasons.append("URL is unusually long")

# @ Symbol Check
if "@" in url:
    risk_score += 2
    reasons.append("Contains @ symbol")

# IP Address Detection
ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"

if re.search(ip_pattern, url):
    risk_score += 3
    reasons.append("Uses IP address instead of domain")

# Suspicious Keywords
keywords = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "banking",
    "password"
]

for keyword in keywords:
    if keyword.lower() in url.lower():
        risk_score += 1
        reasons.append(f"Contains suspicious keyword: {keyword}")

# URL Shorteners
shorteners = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl"
]

for shortener in shorteners:
    if shortener in url.lower():
        risk_score += 2
        reasons.append(f"Uses URL shortener: {shortener}")

# Excessive Hyphens
hyphen_count = url.count("-")

if hyphen_count > 2:
    risk_score += 1
    reasons.append("Contains excessive hyphens")

# Brand Impersonation Check
brands = [
    "paypal",
    "google",
    "facebook",
    "amazon",
    "microsoft",
    "apple"
]

for brand in brands:
    if brand in url.lower():

        if any(char.isdigit() for char in url):
            risk_score += 2
            reasons.append(f"Possible impersonation of {brand}")

# Risk Level
if risk_score <= 2:
    level = "LOW"
elif risk_score <= 5:
    level = "MEDIUM"
else:
    level = "HIGH"

print("\nAnalysis Report")
print("-" * 50)

print(f"Risk Score : {risk_score}/10")
print(f"Risk Level : {level}")

print("\nReasons:")

if reasons:
    for reason in reasons:
        print(f"✓ {reason}")
else:
    print("No suspicious indicators detected")

print("\nRecommendation")
print("-" * 50)

if level == "HIGH":
    print("Avoid entering sensitive information.")
elif level == "MEDIUM":
    print("Proceed with caution.")
else:
    print("URL appears safe.")

print("\nAnalysis Completed")
