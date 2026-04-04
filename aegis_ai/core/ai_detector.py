"""
aegis.ai — AI-Generated Content Detector
Uses the HuggingFace Inference API with prasoonmhwr/ai_detection_model
to detect whether text was written by AI or a human.
This runs ALONGSIDE phishing detection — it does NOT modify phishing scores.
"""
import logging
import os
import requests

logger = logging.getLogger('aegis.ai_detector')

HUGGINGFACE_MODEL = "Hello-SimpleAI/chatgpt-detector-roberta"
HUGGINGFACE_API_URL = f"https://router.huggingface.co/hf-inference/models/{HUGGINGFACE_MODEL}"


def detect_ai_generated(text: str, api_key: str = None) -> dict:
    """
    Detect if text is AI-generated using the HuggingFace Inference API.
    
    Returns:
        {
            'is_ai_generated': bool,
            'ai_probability': float (0.0 - 1.0),
            'label': str ('AI-Generated' or 'Human-Written'),
            'confidence': float (0 - 100),
            'available': bool,
        }
    """
    if not text or len(text.strip()) < 20:
        return {
            'is_ai_generated': False,
            'ai_probability': 0.0,
            'label': 'Insufficient Text',
            'confidence': 0,
            'available': False,
        }

    # Get API key from parameter, env, or Django settings
    hf_token = api_key or os.environ.get('HUGGINGFACE_API_KEY', '')

    if not hf_token:
        # Try loading from Django settings
        try:
            from django.conf import settings
            hf_token = getattr(settings, 'HUGGINGFACE_API_KEY', '')
        except Exception:
            pass

    if not hf_token:
        logger.warning("[ai_detector.py] No HuggingFace API key configured")
        return {
            'is_ai_generated': False,
            'ai_probability': 0.0,
            'label': 'API Key Missing',
            'confidence': 0,
            'available': False,
        }

    try:
        headers = {
            "Authorization": f"Bearer {hf_token}",
            "Content-Type": "application/json",
        }

        # Truncate text to avoid API limits (model uses max_length=128 tokens)
        payload = {
            "inputs": text[:1000],
            "options": {"wait_for_model": True},
        }

        logger.info(f"[ai_detector.py] Sending {len(text[:1000])} chars to HuggingFace API")
        resp = requests.post(HUGGINGFACE_API_URL, headers=headers, json=payload, timeout=30)

        if resp.status_code == 503:
            logger.info("[ai_detector.py] Model is loading, retrying...")
            # Model might be cold-starting
            return {
                'is_ai_generated': False,
                'ai_probability': 0.0,
                'label': 'Model Loading',
                'confidence': 0,
                'available': False,
            }

        resp.raise_for_status()
        result = resp.json()

        logger.info(f"[ai_detector.py] Raw API response: {result}")

        # Parse the HuggingFace text-classification response
        # Format: [[{"label": "LABEL_0", "score": 0.99}, {"label": "LABEL_1", "score": 0.01}]]
        # or [{"label": "LABEL_1", "score": 0.85}, ...]
        if isinstance(result, list):
            # Flatten nested list
            predictions = result[0] if isinstance(result[0], list) else result

            # Find the scores
            ai_score = 0.0
            human_score = 0.0

            for pred in predictions:
                label = pred.get('label', '').upper()
                score = pred.get('score', 0.0)

                # LABEL_1 = AI-generated, LABEL_0 = Human-written
                # (Common convention for binary classifiers)
                if label in ('LABEL_1', 'AI', 'AI-GENERATED', 'FAKE', 'GENERATED', 'CHATGPT'):
                    ai_score = score
                elif label in ('LABEL_0', 'HUMAN', 'HUMAN-WRITTEN', 'REAL'):
                    human_score = score

            # If labels aren't standard, use the highest score logic
            if ai_score == 0.0 and human_score == 0.0 and len(predictions) >= 2:
                # Assume first = human, second = AI (or vice versa)
                ai_score = predictions[1].get('score', 0.0) if len(predictions) > 1 else 0.0
                human_score = predictions[0].get('score', 0.0)

            is_ai = ai_score > 0.5
            confidence = round(max(ai_score, human_score) * 100)

            result_data = {
                'is_ai_generated': is_ai,
                'ai_probability': round(ai_score, 4),
                'label': 'AI-Generated' if is_ai else 'Human-Written',
                'confidence': confidence,
                'available': True,
            }

            logger.info(f"[ai_detector.py] Result: {result_data['label']} ({confidence}%, AI prob: {ai_score:.4f})")
            return result_data

        else:
            logger.warning(f"[ai_detector.py] Unexpected response format: {type(result)}")
            return {
                'is_ai_generated': False,
                'ai_probability': 0.0,
                'label': 'Parse Error',
                'confidence': 0,
                'available': False,
            }

    except requests.exceptions.Timeout:
        logger.warning("[ai_detector.py] HuggingFace API timeout")
        return {
            'is_ai_generated': False, 'ai_probability': 0.0,
            'label': 'Timeout', 'confidence': 0, 'available': False,
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"[ai_detector.py] API request failed: {e}")
        return {
            'is_ai_generated': False, 'ai_probability': 0.0,
            'label': 'API Error', 'confidence': 0, 'available': False,
        }
    except Exception as e:
        logger.error(f"[ai_detector.py] Unexpected error: {e}")
        return {
            'is_ai_generated': False, 'ai_probability': 0.0,
            'label': 'Error', 'confidence': 0, 'available': False,
        }
