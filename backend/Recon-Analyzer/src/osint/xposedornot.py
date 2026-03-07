import logging

import requests

logger = logging.getLogger(__name__)


def breachAnalytics(email: str) -> dict:
    """Get detailed breach analytics for an email."""
    url = f"https://api.xposedornot.com/v1/breach-analytics?email={email}"
    response = requests.get(url, timeout=15)
    response.raise_for_status()
    return response.json()


def checkEmail(email: str) -> dict:
    """Check if an email has been exposed in data breaches."""
    try:
        logger.info(f"Checking email exposure for: {email}")
        url = f"https://api.xposedornot.com/v1/check-email/{email}"

        response = requests.get(url, timeout=15)
        results = response.json()

        if "Error" in results:
            logger.info(f"Email {email} not found in breach databases")
            return {"exposed": False, "message": "Email not found in any breach database"}

        # Get detailed breach analytics
        try:
            breach_analytics = breachAnalytics(email)
            
            breaches = []
            exposed_breaches = breach_analytics.get("ExposedBreaches", {})
            for breach in exposed_breaches.get("breaches_details", []):
                breaches.append(breach)

            breach_metrics = breach_analytics.get("BreachMetrics", {})
            password_strengths = breach_metrics.get("passwords_strength", [])
            risk = breach_metrics.get("risk", {})

            logger.info(f"Email {email} found in {len(breaches)} breaches")
            return {
                "exposed": True,
                "breaches": breaches,
                "breach_count": len(breaches),
                "password_strength": password_strengths,
                "risk": risk,
            }
        except Exception as e:
            logger.warning(f"Could not get detailed breach analytics: {e}")
            return {"exposed": True, "message": "Email found in breaches but details unavailable"}

    except requests.exceptions.Timeout:
        logger.error(f"XposedOrNot request timed out for {email}")
        return {"error": "Request timed out"}
    except requests.exceptions.RequestException as e:
        logger.error(f"XposedOrNot API request failed: {e}")
        return {"error": str(e)}
    except Exception as e:
        logger.error(f"XposedOrNot unexpected error: {e}")
        return {"error": str(e)}
