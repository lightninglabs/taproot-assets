#!/bin/bash

# This script performs different checks on the sample-tapd.conf file:
# 1. Checks that all relevant options of tapd are included.
# 2. Verifies that defaults are labeled if there are also further examples.
# 3. Checks that all default values of tapd are mentioned correctly, including
#    empty defaults and booleans which are set to false by default.

set -e

TAGS="$1"
CONF_FILE=${2:-sample-tapd.conf}

# We are reading the default values of tapd from tapd --help. To avoid
# formatting issues the width of the terminal is set to 240. This needs a
# workaround for CI where we don't have an interactive terminal.
FILE_TMP=$(mktemp)
if [ -t 0 ]; then
    size=($(stty size))
    stty cols 240
    go run -tags="$TAGS" github.com/lightninglabs/taproot-assets/cmd/tapd \
        --help > $FILE_TMP
    stty cols ${size[1]}
else
    tmux new-session -d -s simulated-terminal -x 240 -y 9999
    tmux send-keys -t simulated-terminal.0 "go run -tags=\"$TAGS\" \
        github.com/lightninglabs/taproot-assets/cmd/tapd --help >"$FILE_TMP"; \
        tmux wait -S run" ENTER
    tmux wait-for run
    tmux kill-session -t simulated-terminal
fi

TAPD_HELP="$(cat $FILE_TMP) --end"

# TAPD_OPTIONS is a list of all options of tapd including the equal sign,
# which is needed to distinguish between booleans and other variables.
# It is created by reading the first two columns of tapd --help. 
TAPD_OPTIONS="$(cat $FILE_TMP | \
    awk '{
        option=""; 
        if ($1 ~ /^--/){option=$1};
        if ($2 ~ /^--/){option=$2}; 
        if (match(option,  /--[^=]+[=]*/))
            {printf "%s ", substr(option, RSTART, RLENGTH)}
        } 
        END { printf "%s", "--end"}')"
rm $FILE_TMP

# OPTIONS_NO_CONF is a list of all options without any expected entries in 
# sample-tapd.conf. There's no validation needed for these options. 
OPTIONS_NO_CONF="help lnddir configfile version end"


# OPTIONS_NO_TAPD_DEFAULT_VALUE_CHECK is a list of options with default values
# set, but there aren't any returned defaults by tapd --help. Defaults have to
# be included in sample-tapd.conf but no further checks are performed.
OPTIONS_NO_TAPD_DEFAULT_VALUE_CHECK="tapddir configfile tlscertpath tlskeypath \
    lnd.macaroonpath sqlite.dbfile" 


# EXITCODE is returned at the end after all checks are performed and set to 1 
# if a validation error occurs. COUNTER counts the checked options.
EXITCODE=0
COUNTER=0

for OPTION in $TAPD_OPTIONS; do

    # Determination of the clean name of the option without leading -- and 
    # possible = at the end.
    OPTION_NAME=${OPTION##--}
    OPTION_NAME=${OPTION_NAME%=}


    # Skip if there is no expected entry in sample-tapd.conf.
    echo "$OPTIONS_NO_CONF" | grep -qw $OPTION_NAME && continue
    COUNTER=$((COUNTER+1))

    # Determine the default value of tapd. If the option has no equal sign, 
    # it is boolean and set to false. 
    # For other options we grep the text between the current option and the next
    # option from TAPD_HELP. The default value is given in brackets
    # (default: xx). In the case of durations expressed in hours or minutes, the
    # indications of '0m0s' and '0s' are removed, as they provide redundant
    # information. HOME and HOSTNAME are replaced with general values.
    if [[ "$OPTION" == *"="* ]]; then
        OPTION_NEXT="$(echo "$TAPD_OPTIONS" | sed -E -e "s/.*$OPTION //" \
            -e "s/([^ ]*).*/\1/")"
        DEFAULT_VALUE_LND="$(echo $TAPD_HELP | \
            sed -E -e "s/.*--${OPTION##--}//" \
            -e "s/--${OPTION_NEXT##--}.*//" \
            -e '/(default:.*)/ {' \
                -e 's/.*\(default: ([^)]*)\).*/\1/' -e 't end' -e '}' \
            -e 's/.*//' -e ':end' \
            -e "s#m0s#m#g" \
            -e "s#h0m#h#g" \
            -e "s#$HOME/Library/Application Support/Tapd#~/.lnd#g" \
            -e "s#$HOME#~#g" \
            -e "s#$HOSTNAME#example.com#g")"
    else
        DEFAULT_VALUE_LND="false"
    fi


    # An option is considered included in the sample-tapd.conf if there is
    # a match of the following regex. 
    OPTION_REGEX="^;[ ]*$OPTION_NAME=[^ ]*$"


    # Perform the different checks now. If one fails we move to the next option.
    # 1. check if the option is included in the sample-tapd.conf.
    if [ $(grep -c "$OPTION_REGEX" $CONF_FILE) -eq 0 ]; then
        echo "Option $OPTION_NAME: no default or example included in \
            sample-tapd.conf"
        EXITCODE=1
        continue
    fi
    
    # Skip if no default value check should be performed.
    echo "$OPTIONS_NO_TAPD_DEFAULT_VALUE_CHECK" | grep -wq $OPTION_NAME && continue

    # 2. Check that the default value is labeled if it is included multiple 
    # times.
    if [ $(grep -c "$OPTION_REGEX" $CONF_FILE) -ge 2 ]; then
        
        # For one option there has to be a preceding line "; Default:" 
        # If it matches we grep the default value from the file.
        if grep -A 1 "^; Default:" $CONF_FILE  | grep -q "$OPTION_REGEX"; then
            DEFAULT_VALUE_CONF="$(grep -A 1 "^; Default:" $CONF_FILE  | \
               grep "$OPTION_REGEX" | cut -d= -f2)"

        else
            echo "Option $OPTION_NAME: mentioned multiple times in \
                sample-tapd.conf but without a default value"
            
            EXITCODE=1
            continue
        fi
    else
        # If there is only one entry in sample-tapd.conf we grep the default 
        # value.
        DEFAULT_VALUE_CONF=$(grep "$OPTION_REGEX" $CONF_FILE | cut -d= -f2)
    fi
    
    # 3. Compare the default value of tapd --help with the value in the
    # sample-tapd.conf file. If tapd doesn't provide a default value, it is
    # allowed for the value in the file to be '0' or '0s'.
    if [ ! "$DEFAULT_VALUE_LND" == "$DEFAULT_VALUE_CONF" ]; then
        
        if [ -z "$DEFAULT_VALUE_LND" ] && [ "$DEFAULT_VALUE_CONF" == "0" ]; then
            true

        elif [ -z "$DEFAULT_VALUE_LND" ] && \
                [ "$DEFAULT_VALUE_CONF" == "0s" ]; then
            true

        else
            echo "Option $OPTION_NAME: defaults don't match - sample-tapd.conf: \
                '$DEFAULT_VALUE_CONF', lnd: '$DEFAULT_VALUE_LND'"
            
            EXITCODE=1
            continue
        fi
    fi
    
done

echo "$COUNTER options were checked"
exit $EXITCODE
