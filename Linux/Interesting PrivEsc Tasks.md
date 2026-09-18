
## Cron abuse

Root run those scripts over cron. Do you have any idea how to escalate to root if you are just www-data?

```bash
#!/bin/bash

cat /var/www/financial_data/transactions.log >> /var/www/backups/backup_transactions.log

  

#!/bin/bash

cd /var/www

tar czf /backup/www_$(date +%F).tar.gz *
```