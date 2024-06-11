from streamfabcdm import StreamFabCdm

kid = "71769f4d4b72473f80915cf6436a3476" # Replace with one of your video kid here
table = "disneyplus_us" # table can be a service from one of the below values

'''
[
    "abema", "abematv", "amazon_pm", "amazon_jp", "amazon_us", "amazon_uk",
    "amazon_de", "appletv", "canal", "paramount", "channel", "crackle",
    "crunchyroll", "discovery", "disneyplus_us", "disneyplus_jp", "unext",
    "dtv", "fod", "gyao", "hbo_europe", "hbomax", "hulu_us", "hulu_jp", "joyn",
    "mgstage", "netflix", "paravi", "peacock", "pluto", "rakuten", "roku",
    "skyshowtime", "stan", "telasa", "tubitv", "tvnow", "viki"
]
'''

stream_fab = StreamFabCdm()

keys = stream_fab.get_cached_keys(kid,table)
print(keys)