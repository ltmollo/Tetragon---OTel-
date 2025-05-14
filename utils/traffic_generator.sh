#!/bin/bash

URL="http://localhost:8080"
for i in {1..100}
do
  wget -qO- $URL
done