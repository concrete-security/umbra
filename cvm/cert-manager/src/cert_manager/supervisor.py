"""
Supervisor class

Manages different processes (nginx and cert-manager) via Supervisord.
"""

import os
import logging
import subprocess
from typing import Optional

logger = logging.getLogger("cert-manager")


class Supervisor:
    """Supervisor manages both Nginx and this Cert Manager.
    This class is a helper for configuring Nginx (base/https) and restarting it via Supervisor.
    """

    SUPERVISOR_CONF_PATH = "/etc/supervisor/conf.d/supervisord.conf"
    NGINX_CONF_PATH = "/etc/nginx/conf.d/default.conf"
    NGINX_BASE_CONF_PATH = os.path.join(
        os.path.dirname(__file__), "..", "..", "nginx_conf", "base.conf"
    )
    NGINX_HTTPS_CONF_PATH = os.path.join(
        os.path.dirname(__file__), "..", "..", "nginx_conf", "https.conf"
    )

    def __init__(
        self,
        supervisor_conf_path: Optional[str] = None,
        nginx_conf_path: Optional[str] = None,
        nginx_base_conf_path: Optional[str] = None,
        nginx_https_conf_path: Optional[str] = None,
    ):
        self.supervisor_conf_path = (
            supervisor_conf_path if supervisor_conf_path else self.SUPERVISOR_CONF_PATH
        )
        self.nginx_conf_path = nginx_conf_path if nginx_conf_path else self.NGINX_CONF_PATH
        self.nginx_base_conf_path = (
            nginx_base_conf_path if nginx_base_conf_path else self.NGINX_BASE_CONF_PATH
        )
        self.nginx_https_conf_path = (
            nginx_https_conf_path if nginx_https_conf_path else self.NGINX_HTTPS_CONF_PATH
        )

    def restart_nginx(self):
        """
        Restart nginx via supervisorctl.

        Raises:
            Exception: If the restart command fails or times out.
        """

        cmd = ["supervisorctl", "-c", self.supervisor_conf_path, "restart", "nginx"]

        logger.info(f"Restarting nginx via supervisorctl: {' '.join(cmd)}")

        if not os.path.exists(self.supervisor_conf_path):
            raise Exception(
                f"Supervisor configuration file not found at {self.supervisor_conf_path}"
            )

        try:
            result = subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,  # 30 second timeout for restart
            )

            logger.info("Nginx restart completed successfully")
            logger.debug(f"Supervisorctl stdout: {result.stdout}")

            if result.stderr:
                logger.debug(f"Supervisorctl stderr: {result.stderr}")

        except subprocess.CalledProcessError as e:
            logger.error(f"Nginx restart failed with exit code {e.returncode}")
            logger.error(f"Supervisorctl stderr: {e.stderr}")
            logger.error(f"Supervisorctl stdout: {e.stdout}")
            raise Exception("Nginx restart failed (see logs for more info)")

        except subprocess.TimeoutExpired:
            logger.error("Nginx restart command timed out")
            raise Exception("Nginx restart command timed out")

        except Exception as e:
            logger.error(f"Unexpected error restarting nginx: {e}")
            raise

    def setup_nginx_base_config(self):
        """
        Set up nginx with the base configuration and restart nginx.

        This configures nginx with HTTP-only settings, typically used during
        initial setup or when HTTPS certificates are not yet available.

        Raises:
            Exception: If the configuration setup or restart fails.
        """
        logger.info("Setting up nginx with base configuration (no HTTPS)")

        try:
            if not os.path.exists(self.nginx_base_conf_path):
                raise Exception(
                    f"Base nginx configuration not found at {self.nginx_base_conf_path}"
                )

            with open(self.nginx_base_conf_path, "r") as src:
                base_config = src.read()

            with open(self.nginx_conf_path, "w") as dst:
                dst.write(base_config)

            logger.info(f"Base configuration written to {self.nginx_conf_path}")

        except Exception as e:
            logger.error(f"Failed to setup nginx base configuration: {e}")
            raise

        # Restart nginx to apply the new configuration
        try:
            self.restart_nginx()
        except Exception as e:
            logger.error(f"Failed to restart nginx: {e}")
            raise

    def setup_nginx_https_config(self):
        """
        Set up nginx with the base + HTTPS configuration and restart nginx.

        This configures nginx with both HTTP and HTTPS settings, typically used
        after SSL certificates have been obtained and are available.

        Raises:
            Exception: If the configuration setup or restart fails.
        """
        logger.info("Setting up nginx with base + HTTPS configuration")

        try:
            if not os.path.exists(self.nginx_base_conf_path):
                raise Exception(
                    f"Base nginx configuration not found at {self.nginx_base_conf_path}"
                )
            if not os.path.exists(self.nginx_https_conf_path):
                raise Exception(
                    f"HTTPS nginx configuration not found at {self.nginx_https_conf_path}"
                )

            # Read both configurations
            with open(self.nginx_base_conf_path, "r") as src:
                base_config = src.read()

            with open(self.nginx_https_conf_path, "r") as src:
                https_config = src.read()

            # Combine configurations (base + https)
            combined_config = base_config + "\n" + https_config

            # Write combined configuration to nginx conf directory
            with open(self.nginx_conf_path, "w") as dst:
                dst.write(combined_config)

            logger.info(f"Combined base + HTTPS configuration written to {self.nginx_conf_path}")

        except Exception as e:
            logger.error(f"Failed to setup nginx HTTPS configuration: {e}")
            raise

        # Restart nginx to apply the new configuration
        try:
            self.restart_nginx()
        except Exception as e:
            logger.error(f"Failed to restart nginx: {e}")
            raise
