ldd $(which $1) | grep -oP '(?<=.\s=>\s)(.*)(?=\s\(.*\))' | xargs -I '{}' cp -n '{}' $2