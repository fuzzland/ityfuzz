cd ui
gunicorn backend:app --bind 0.0.0.0:8000 &
pid1=$!
cd ..

cd proxy
gunicorn main:app --bind 0.0.0.0:5003 &
pid2=$!
cd ..


trap 'kill $pid1; kill $pid2; exit' ERR
wait $pid1
wait $pid2
