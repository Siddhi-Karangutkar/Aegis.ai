"""
aegis.ai — Docker Sandbox Manager
Manages the Docker container lifecycle for attachment sandboxing.
Handles auto-build, container execution, and result parsing.
"""
import subprocess
import json
import os
import logging
import tempfile
import shutil
import time

logger = logging.getLogger('aegis.sandbox')

# ─── Configuration ───────────────────────────────────────────────────
SANDBOX_IMAGE_NAME = 'aegis-sandbox'
SANDBOX_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'sandbox')
CONTAINER_TIMEOUT = 30      # Max seconds a container can run
CONTAINER_MEMORY = '128m'   # Memory limit
CONTAINER_CPUS = '0.5'      # CPU limit

# Track whether we've verified the image exists this session
_image_verified = False


def _run_docker_command(args: list, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a docker command and return the result."""
    cmd = ['docker'] + args
    logger.debug(f"[docker_sandbox] Running: {' '.join(cmd)}")
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def is_docker_available() -> bool:
    """Check if Docker is running and accessible."""
    try:
        result = _run_docker_command(['info'], timeout=10)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def image_exists() -> bool:
    """Check if the aegis-sandbox Docker image is already built."""
    try:
        result = _run_docker_command(['images', '-q', SANDBOX_IMAGE_NAME], timeout=10)
        return bool(result.stdout.strip())
    except Exception:
        return False


def build_image() -> bool:
    """Build the aegis-sandbox Docker image from the sandbox directory."""
    logger.info(f"[docker_sandbox] Building Docker image '{SANDBOX_IMAGE_NAME}' from {SANDBOX_DIR}")

    if not os.path.isdir(SANDBOX_DIR):
        logger.error(f"[docker_sandbox] Sandbox directory not found: {SANDBOX_DIR}")
        return False

    dockerfile = os.path.join(SANDBOX_DIR, 'Dockerfile')
    if not os.path.isfile(dockerfile):
        logger.error(f"[docker_sandbox] Dockerfile not found: {dockerfile}")
        return False

    try:
        result = _run_docker_command(
            ['build', '-t', SANDBOX_IMAGE_NAME, SANDBOX_DIR],
            timeout=300,  # Building can take a while the first time
        )

        if result.returncode == 0:
            logger.info(f"[docker_sandbox] ✅ Image built successfully")
            return True
        else:
            logger.error(f"[docker_sandbox] ❌ Build failed:\n{result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        logger.error("[docker_sandbox] ❌ Image build timed out (5 min)")
        return False


def ensure_image_built() -> bool:
    """Ensure the sandbox image exists; build it if it doesn't. Cached per session."""
    global _image_verified

    if _image_verified:
        return True

    if not is_docker_available():
        logger.warning("[docker_sandbox] Docker is not running or not installed")
        return False

    if image_exists():
        logger.info("[docker_sandbox] Image already exists, skipping build")
        _image_verified = True
        return True

    # Auto-build
    success = build_image()
    if success:
        _image_verified = True
    return success


def run_sandbox(file_path: str, filename: str, timeout: int = None) -> dict:
    """
    Run a file through the Docker sandbox for deep analysis.

    Args:
        file_path: Absolute path to the file on the host
        filename: Original filename (used for extension-based analysis)
        timeout: Max seconds for container execution

    Returns:
        dict with 'score', 'reasons', 'analysis' keys
    """
    if timeout is None:
        timeout = CONTAINER_TIMEOUT

    # ── 1. Ensure image is ready ──
    if not ensure_image_built():
        logger.warning("[docker_sandbox] Docker unavailable, falling back to static analysis")
        return {
            'score': 0.0,
            'reasons': ['Docker sandbox unavailable — static analysis only'],
            'analysis': {'sandbox': 'unavailable'},
        }

    # ── 2. Prepare the file ──
    # Docker on Windows needs the path in a specific format
    abs_path = os.path.abspath(file_path)

    # Convert Windows path to Docker-compatible mount format
    # e.g., D:\foo\bar.pdf -> /d/foo/bar.pdf (for Docker Desktop on Windows)
    docker_mount_path = abs_path
    if os.name == 'nt':
        # Windows: convert backslashes and drive letter
        docker_mount_path = abs_path.replace('\\', '/')
        if len(docker_mount_path) >= 2 and docker_mount_path[1] == ':':
            docker_mount_path = '/' + docker_mount_path[0].lower() + docker_mount_path[2:]

    # ── 3. Run the container ──
    container_args = [
        'run',
        '--rm',                          # Auto-remove after exit
        '--network=none',                # No network access
        f'--memory={CONTAINER_MEMORY}',  # Memory limit
        f'--cpus={CONTAINER_CPUS}',      # CPU limit
        '--read-only',                   # Read-only filesystem
        '--tmpfs', '/tmp:size=10m',      # Small writable tmp for libraries
        '-v', f'{docker_mount_path}:/sample/attachment:ro',  # Mount file read-only
        SANDBOX_IMAGE_NAME,
        '/sample/attachment',
        filename,
    ]

    logger.info(f"[docker_sandbox] Analyzing: {filename} ({os.path.getsize(abs_path)} bytes)")
    start_time = time.time()

    try:
        result = _run_docker_command(container_args, timeout=timeout)
        elapsed = round(time.time() - start_time, 2)

        if result.returncode != 0:
            logger.warning(f"[docker_sandbox] Container exited with code {result.returncode}")
            logger.warning(f"[docker_sandbox] stderr: {result.stderr[:500]}")
            # Still try to parse stdout in case there's partial output
            if not result.stdout.strip():
                return {
                    'score': 0.0,
                    'reasons': [f'Sandbox container error (exit code {result.returncode})'],
                    'analysis': {
                        'sandbox': 'docker',
                        'error': result.stderr[:500],
                        'elapsed_seconds': elapsed,
                    },
                }

        # ── 4. Parse JSON output ──
        try:
            output = json.loads(result.stdout.strip())
            output['analysis'] = output.get('analysis', {})
            output['analysis']['elapsed_seconds'] = elapsed
            logger.info(
                f"[docker_sandbox] ✅ Analysis complete in {elapsed}s — "
                f"score={output.get('score', 0)}, "
                f"reasons={len(output.get('reasons', []))}"
            )
            return output

        except json.JSONDecodeError as e:
            logger.error(f"[docker_sandbox] Failed to parse container output: {e}")
            logger.error(f"[docker_sandbox] Raw output: {result.stdout[:500]}")
            return {
                'score': 0.0,
                'reasons': ['Sandbox output parsing error'],
                'analysis': {
                    'sandbox': 'docker',
                    'raw_output': result.stdout[:300],
                    'error': str(e),
                    'elapsed_seconds': elapsed,
                },
            }

    except subprocess.TimeoutExpired:
        logger.error(f"[docker_sandbox] Container timed out after {timeout}s")
        # Kill the container if it's still running
        return {
            'score': 0.5,
            'reasons': [f'Sandbox analysis timed out ({timeout}s) — file may be adversarial'],
            'analysis': {
                'sandbox': 'docker',
                'timeout': True,
            },
        }

    except FileNotFoundError:
        logger.error("[docker_sandbox] Docker executable not found in PATH")
        return {
            'score': 0.0,
            'reasons': ['Docker not found — static analysis only'],
            'analysis': {'sandbox': 'unavailable'},
        }
