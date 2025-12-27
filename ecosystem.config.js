/**
 * PM2 Configuration for ByteLeap Miner
 *
 * Usage:
 *   Start all:     pm2 start ecosystem.config.js
 *   Start worker:  pm2 start ecosystem.config.js --only worker
 *   Start miner:   pm2 start ecosystem.config.js --only miner
 *   Stop all:      pm2 stop ecosystem.config.js
 *   Restart all:   pm2 restart ecosystem.config.js
 *   Logs:          pm2 logs
 *   Monitor:       pm2 monit
 */

module.exports = {
  apps: [
    {
      name: 'byteleap-worker',
      script: 'scripts/run_worker.py',
      interpreter: 'python3',
      args: '--config config/worker_config.yaml',
      cwd: './',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '4G',
      error_file: 'logs/pm2-worker-error.log',
      out_file: 'logs/pm2-worker-out.log',
      log_file: 'logs/pm2-worker-combined.log',
      time: true,
      merge_logs: true,
      env: {
        PYTHONUNBUFFERED: '1',
        PYTHONPATH: '.',
      },
      // Restart strategy
      min_uptime: '10s',
      max_restarts: 10,
      restart_delay: 5000,
      // Kill timeout
      kill_timeout: 30000,
      // Listen timeout
      listen_timeout: 10000,
    },
    {
      name: 'byteleap-miner',
      script: 'scripts/run_miner.py',
      interpreter: 'python3',
      args: '--config config/miner_config.yaml',
      cwd: './',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '2G',
      error_file: 'logs/pm2-miner-error.log',
      out_file: 'logs/pm2-miner-out.log',
      log_file: 'logs/pm2-miner-combined.log',
      time: true,
      merge_logs: true,
      env: {
        PYTHONUNBUFFERED: '1',
        PYTHONPATH: '.',
      },
      // Restart strategy
      min_uptime: '10s',
      max_restarts: 10,
      restart_delay: 5000,
      // Kill timeout
      kill_timeout: 30000,
      // Listen timeout
      listen_timeout: 10000,
    },
  ],
};
