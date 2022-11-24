#! /bin/bash

function usage() {
    echo "Usage: ./demo.sh [OPTIONS] COMMAND [ARG...]

Options:

-h, --help Display this help.

COMMAND may be one of:

build      Build the Docker image for the demo.
regenerate Regenerate the set of SCHC rules.
test       Run the test suite.
run        Run a demo command.
context    View and manipulate filesystem context
"
}

function build() {

    echo "$0 $@"

    if [[ ! -z "$1" ]] && [[ "$1" == legacy ]]; then
	echo docker build -f legacy.Dockerfile . -t schcoscore
	docker build -f legacy.Dockerfile -t schcoscore .
    else
	echo docker build . -t schcoscore
	docker build -t schcoscore .

    fi

}

function regenerate_rules() {

    ./demo.sh run bash -c 'cd schc && python makeRule.py'

}

function show_context() {
    find oscore_dir -type f | while read filename; do
	printf "${filename}:\n\n"
	cat "$filename"
	printf "\n--\n"
    done;
}

function clear_context() {
    rm -rf oscore_dir
    echo "Cleared filesystem context in ./oscore_dir/"
}

function context() {
    case "$1" in
	show)
	    show_context
	    ;;
	clear)
	    clear_context
	    ;;
	"")
	    echo "Must provide context command, choose from:"
	    echo "- show     Show files that make up the context"
	    echo "- clear    Clear context files"
	    exit 1
	    ;;
	*)
	    echo "Unrecognized context command: $1"
	    usage
	    exit 1
	    ;;
    esac
}

function run() {
    echo "$0 $@"

    case "$1" in
	get-temperature)
	    echo "Running get-temperature demo"
	    ./demo.sh run python ./run_demo.py \
		      --mtype CON \
		      --code GET \
		      --uri coap://127.0.0.1/temperature \
		      --mid 1 \
		      --token 0x82 \
		      --verbose \
		      --with-dump \
		      --oscore-dir oscore_dir
	    ;;
	give-temperature)
	    echo "Running give-temperature demo"
	    ./demo.sh run python ./run_demo.py \
		      --mtype ACK \
		      --code CONTENT\
		      --mid 2\
		      --token 0x82 \
		      --verbose \
		      --with-dump \
		      --role server \
		      --oscore-dir oscore_dir \
		      --payload 32332043
	    ;;
	*)
	    docker-compose run --rm \
			   -e LOGLEVEL="$LOGLEVEL" \
			   -e _DOCKER_APP_WORK_DIR="$_DOCKER_APP_WORK_DIR" \
			   main "$@"
	    ;;
    esac
}

function run_tests() {
    ./demo.sh run bash -c 'PYTHONPATH=$(pwd) pytest -s ./demo_tests'
}


if [[ -z "$1" ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    usage
    exit 1
fi

case "$1" in
    build)
	build "${@:2}"
	;;
    run)
	run "${@:2}"
	;;
    regenerate)
	regenerate_rules
	;;
    test)
	run_tests "${@:2}"
	;;
    context)
	context "${@:2}"
	;;
    *)
	echo "Unrecognized command: $1"
	usage
	exit 1
	;;
esac
