# WIPSTERv2
 Web Interface Portal &amp; Security Threat Engine for REMnux version 2
 
 Rewritten version of https://github.com/TheDr1ver/WIPSTER
 
## Notes
To start the server run: `python manage.py runserver`

If you edit the Models, run the following commands to migrate the models and restart the server:
```
python manage.py makemigrations sample_analysis
python manage.py migrate
python manage.py runserver
```
