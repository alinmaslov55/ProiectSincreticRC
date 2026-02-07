#!/bin/bash

case "$1" in
    "clean")
        rm -rf logs/*.log
        echo "Logs cleared."
        ;;
    "watch")
        echo "Watching live server logs..."
        tail -f logs/server_thread_*.log
        ;;
    "results")
        if [ -f "exam_results.csv" ]; then
            column -s, -t < exam_results.csv
        else
            echo "No results found yet."
        fi
        ;;
    *)
        echo "Usage: ./manage.sh {clean|watch|results}"
        ;;
esac