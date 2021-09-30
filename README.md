## stream.pcap

This pcap is made by netcat'ing over `stream.txt`. It contains 10000 random
ascii characters, then the string:

```
:generator-<X>:
```

where `<X>` is the iteration count, so with 1000 iterations we have:

```
<random>:generator-0:<random>:generator-1:<random>...<random>:generator-999:
```

## Tests

### content-only

Rule: `alert tcp any any -> any any (msg:"TEST CONTENT"; content:":generator-"; sid:2; rev:1;)`

Matches 911 times.  Seems to miss a few at random.

Extending the rule to: `alert tcp any any -> any any (msg:"TEST CONTENT"; content:":generator-"; pcre:"/(generator-\d+)/ flow:counter"; sid:2; rev:1;)` to capture which ones its catching we see:

- generator-0
- generator-1
- generator-4
- generator-4 (yes, duplicate)
- generator-7
- generator-13

### pcre-only

Rule: `alert tcp any any -> any any (msg:"TEST PCRE"; pcre:"/:generator-(\d+):/, pkt:generator/counter"; sid:1; rev:1;)`

Matches 1443 times

### pcre-with-content

Rule: `alert tcp any any -> any any (msg:"TEST PCRE"; content:":generator"; pcre:"/:generator-(\d+):/, flow:generator/counter"; sid:3; rev:1;)`

Matches 907 times. I'd expect 911 from the `content-only` test, but the regular
expression limits the matches further.
