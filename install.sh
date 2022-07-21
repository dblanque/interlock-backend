#!/bin/bash

# Creates default superuser
echo "from django.contrib.auth import get_user_model; User = get_user_model(); User.objects.create_default_superuser()" | python manage.py shell