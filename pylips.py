#!/usr/bin/env python3
#  version 1.3.2

import argparse
import configparser
import json
import os
import platform
import random
import string
import subprocess
import sys
import time
from base64 import b64decode, b64encode
from typing import Any, Callable, List, Literal

import paho.mqtt.client as mqttc
import requests
from Crypto.Hash import HMAC, SHA
from requests.auth import HTTPDigestAuth

#  suppress "Unverified HTTPS request is being made" error message
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
session = requests.Session()
session.verify = False
session.mount('https://', requests.adapters.HTTPAdapter(pool_connections=1))

#  key used for generated the HMAC signature
secret_key = "JCqdN5AcnAHgJYseUn7ER5k3qgtemfUvMRghQpTfTZq7Cvv8EPQPqfz6dDxPQPSu4gKFPWkJGw32zyASgJkHwCjU"

parser = argparse.ArgumentParser(description="Control Philips TV API (versions 5 and 6)")
parser.add_argument("--host", dest="host", help="TV's ip address")
parser.add_argument("--user", dest="user", help="Username")
parser.add_argument("--pass", dest="password", help="Password")
parser.add_argument("--command", help="Command to run", default="")
parser.add_argument("--path", dest="path", help="API's endpoint path")
parser.add_argument("--body", dest="body", help="Body for post requests")
parser.add_argument("--verbose", dest="verbose", help="Display feedback")
parser.add_argument("--apiv", dest="apiv", help="Api version", default="")
parser.add_argument("--config", dest="config", help="Path to config file", default=os.path.dirname(os.path.realpath(__file__))+os.path.sep+"settings.ini")

args = parser.parse_args()


def eprint(*values: object,
           verbose=True,
           sep=" ",
           end="\n",
           flush=False):
    """
    Prints to `stderr` if `verbose == True`.
    """
    if verbose:
        print(*values,
              sep=sep,
              end=end,
              file=sys.stderr,
              flush=flush)


class Pylips:
    class Ex:
        """
        Custom exceptions.
        """
        class ConfigError(Exception):
            pass

        class ParamError(Exception):
            pass

        class ConnectionError(ConnectionError):
            pass

        class PairingError(Exception):
            pass

    def __init__(self, ini_file):
        #  read config file
        self.config = configparser.ConfigParser()

        if os.path.isfile(ini_file) == False:
            raise Pylips.Ex.ConfigError("Config file '" + ini_file + "' not found")
        try:
            self.config.read(ini_file)
        except:
            raise Pylips.Ex.ConfigError("Config file '" + ini_file + "' exists but unreadable")
        self.ini_file = ini_file

        if args.host in [None, ""] and self.config["TV"]["host"] == "":
            raise Pylips.Ex.ConfigError("TV IP-address not specified: set '[TV]/host' within '" + ini_file + "' (or provide a '--host' arg)")

        #  check verbose option
        if self.config["DEFAULT"]["verbose"] == "True":
            self.verbose = True
        else:
            self.verbose = False
        #  timeout for requests / pings
        self.timeout = max(float(self.config["DEFAULT"]["request_timeout"]), 0.1)
        #  number of retries for requests / pings
        self.num_retries = max(int(self.config["DEFAULT"]["num_retries"]), 1)

        #  override config with any directly passed args
        if len(sys.argv) > 1:
            if args.verbose is not None:
                if args.verbose.lower() in ["true", "y", "1"]:
                    self.verbose = True
                else:
                    self.verbose = False
            if args.host:
                self.config["TV"]["host"] = args.host
            if args.user and args.password:
                self.config["TV"]["user"] = args.user
                self.config["TV"]["pass"] = args.password
                self.config["TV"]["port"] = "1926"
                self.config["TV"]["protocol"] = "https://"
            elif ((len(self.config["TV"]["user"]) == 0 or len(self.config["TV"]["pass"]) == 0) and
                  self.config["TV"]["port"] == "1926"):
                raise Pylips.Ex.ParamError("Bad credentials: if you have an Android TV, specify both '--user' and '--pass'")
            if len(args.apiv) != 0:
                self.config["TV"]["apiv"] = args.apiv

        #  make script directly executable
        if platform.system().lower() != "windows" and not os.access(__file__, os.X_OK):
            try:
                subprocess.call(["chmod", "+x", __file__], stdout=subprocess.DEVNULL)
                eprint(f"'{__file__}' is now executable",
                       verbose=self.verbose)
            except:
                eprint(f"Error: Unable to make '{os.path.basename(__file__)}' executable",
                       verbose=self.verbose)

        #  check API version
        if len(self.config["TV"]["apiv"]) == 0:
            if self.find_api_version(self.verbose):
                if self.check_if_paired() is False:
                    eprint("No valid credentials found, starting pairing process…")
                    self.pair()
                with open(ini_file, "w") as configfile:
                    self.config.write(configfile)
            else:
                if self.is_online(self.config["TV"]["host"],
                                  verbose=self.verbose,
                                  num_retries=1):
                    raise Pylips.Ex.ConnectionError("IP '" + self.config["TV"]["host"] + "' online but no known API found")
                else:
                    raise Pylips.Ex.ConnectionError("IP '" + self.config["TV"]["host"] + "' offline")

        #  load API commands
        with open(os.path.dirname(os.path.realpath(__file__))+"/available_commands.json") as json_file:
            self.available_commands = json.load(json_file)

        #  start MQTT listener and updater if required
        if ((len(sys.argv) == 1 or (len(sys.argv) == 3 and sys.argv[1] == "--config")) and
                self.config["DEFAULT"]["mqtt_listen"] == "True"):
            if len(self.config["MQTT"]["host"]) > 0:
                #  listen for MQTT messages to run commands
                self.start_mqtt_listener()
                if self.config["DEFAULT"]["mqtt_update"] == "True":
                    #  update TV status and publish any changes
                    self.last_status = {"powerstate": None, "volume": None, "muted": False, "cur_app": None, "ambilight": None, "ambihue": False}
                    self.start_mqtt_updater(self.verbose)
            else:
                raise Pylips.Ex.ConfigError("Unable to use MQTT: set '[MQTT]/host' within '" + ini_file + "'")
        elif len(sys.argv) > 1:
            #   parse passed args and required command
            body = args.body
            path = args.path
            if args.command == "get":
                self.get(path,
                         verbose=self.verbose)
            elif args.command == "post":
                self.post(path,
                          body=body,
                          verbose=self.verbose)
            elif len(args.command) > 0:
                if not self.run_command(args.command,
                                        body=body,
                                        verbose=self.verbose):
                    raise Pylips.Ex.ConnectionError("Cannot reach the API")
            else:
                raise Pylips.Ex.ParamError("No '--command' arg provided")
        else:
            raise Pylips.Ex.ParamError("No '--command' arg provided (alternatively enable '[DEFAULT]/mqtt_listen' within '" + ini_file + "')")

    def is_online(self,
                  host: str,
                  verbose=True,
                  num_retries: int = None,
                  retry_delay: float = 0,
                  on_attempt_fail: Callable[[], Any] = None):
        """
        Tests TV connection (ie. whether `host` responds to ping request(s)).
        """
        max_retries = num_retries if num_retries else self.num_retries
        num_packets_opt = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", num_packets_opt, "1", host]
        attempt = 1
        while attempt <= max_retries:
            eprint(f"\n> (PING attempt {attempt}/{max_retries})",
                   verbose=verbose)
            try:
                return subprocess.call(command,
                                       timeout=self.timeout,
                                       stdout=sys.stderr if verbose else subprocess.DEVNULL) == 0
            except subprocess.TimeoutExpired:
                eprint("PING timed out",
                       verbose=verbose)
            attempt += 1
            if on_attempt_fail:
                on_attempt_fail()
            if retry_delay and attempt <= max_retries:
                eprint(f"Waiting {retry_delay}s before retry…",
                       verbose=verbose)
                time.sleep(retry_delay)
        return False

    def find_api_version(self,
                         verbose=True,
                         possible_ports: List[int] = [1925],
                         possible_api_versions: List[int] = [6, 5, 1]):
        """
        Finds API version & updates `self.config["TV"]["apiv"]`
        """
        eprint("Checking API version and port…",
               verbose=verbose)
        protocol = "http://"
        for port in possible_ports:
            for api_version in possible_api_versions:
                try:
                    target = f"{protocol}{self.config['TV']['host']}:{port}/{api_version}/system"
                    eprint(f"Trying api v{api_version}: '{target}'…",
                           verbose=verbose)
                    r = session.get(target,
                                    verify=False,
                                    timeout=self.timeout)
                except requests.exceptions.ConnectionError:
                    eprint("Connection refused",
                           verbose=verbose)
                    continue
                if r.status_code == 200:
                    if "api_version" in r.json():
                        self.config["TV"]["apiv"] = str(r.json()["api_version"]["Major"])
                    else:
                        eprint(f"Could not find a valid API version: Pylips will try to use v{api_version}")
                        self.config["TV"]["apiv"] = str(api_version)
                    if ("featuring" in r.json() and
                        "systemfeatures" in r.json()["featuring"] and
                        "pairing_type" in r.json()["featuring"]["systemfeatures"] and
                            r.json()["featuring"]["systemfeatures"]["pairing_type"] == "digest_auth_pairing"):
                        self.config["TV"]["protocol"] = "https://"
                        self.config["TV"]["port"] = "1926"
                    else:
                        self.config["TV"]["protocol"] = "http://"
                        self.config["TV"]["port"] = "1925"
                    return True
        return False

    def check_if_paired(self):
        """
        Returns `True` if already paired or using non-Android TVs.
        """
        if (self.config["TV"]["protocol"] == "https://" and
                (len(str(self.config["TV"]["user"])) == 0 or len(str(self.config["TV"]["pass"])) == 0)):
            return False
        return True

    def createDeviceId(self):
        """
        Creates random device id.
        """
        return "".join(random.SystemRandom().choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(16))

    def create_signature(self, secret_key, to_sign):
        """
        Creates signature.
        """
        sign = HMAC.new(secret_key, to_sign, SHA)
        return str(b64encode(sign.hexdigest().encode()))

    def getDeviceSpecJson(self, config):
        """
        Creates device spec JSON
        """
        device_spec = {"device_name": "heliotrope", "device_os": "Android", "app_name": "Pylips", "type": "native"}
        device_spec["app_id"] = config["application_id"]
        device_spec["id"] = config["device_id"]
        return device_spec

    def pair(self):
        """
        Initiates pairing with a TV.
        """
        payload = {}
        payload["application_id"] = "app.id"
        payload["device_id"] = self.createDeviceId()
        self.config["TV"]["user"] = payload["device_id"]
        data = {"scope":  ["read", "write", "control"]}
        data["device"] = self.getDeviceSpecJson(payload)
        eprint("Sending pairing request…")
        self.pair_request(data)

    def pair_request(self,
                     data: str):
        """
        Pairs with a TV.
        """
        target = f"https://{self.config['TV']['host']}:1926/'{self.config['TV']['apiv']}/pair/request"
        eprint(f"\nSending POST request to '{target}'…")
        response = {}
        r = session.post(target,
                         json=data,
                         verify=False,
                         timeout=self.timeout)
        if r.json() is not None:
            if r.json()["error_id"] == "SUCCESS":
                response = r.json()
            else:
                raise Pylips.Ex.PairingError(r.json())
        else:
            raise Pylips.Ex.ConnectionError("Cannot reach the API")

        auth_Timestamp = response["timestamp"]
        self.config["TV"]["pass"] = response["auth_key"]
        data["device"]["auth_key"] = response["auth_key"]
        pin = input("Enter onscreen passcode: ")

        auth = {"auth_AppId": "1"}
        auth["pin"] = str(pin)
        auth["auth_timestamp"] = auth_Timestamp
        auth["auth_signature"] = self.create_signature(b64decode(secret_key), str(auth_Timestamp).encode() + str(pin).encode())

        grant_request = {}
        grant_request["auth"] = auth
        data["application_id"] = "app.id"
        data["device_id"] = self.config["TV"]["user"]
        grant_request["device"] = self.getDeviceSpecJson(data)

        eprint("Attempting to pair…")
        self.pair_confirm(grant_request)

    def pair_confirm(self,
                     data: str):
        """
        Confirms pairing with a TV.
        """
        attempt = 1
        while attempt <= 10:
            if attempt > 1:
                eprint("Resending pair confirm request…")
            try:
                r = session.post(f"https://{self.config['TV']['host']}:1926/{self.config['TV']['apiv']}/pair/grant",
                                 json=data,
                                 verify=False,
                                 auth=HTTPDigestAuth(self.config["TV"]["user"], self.config["TV"]["pass"]), timeout=self.timeout)
                eprint("Username for subsequent calls is:", self.config["TV"]["user"])
                eprint("Password for subsequent calls is:", self.config["TV"]["pass"])
                eprint(f"Credentials updated within '{self.ini_file}'")
                return
            except:
                pass
            attempt += 1
        raise Pylips.Ex.ConnectionError("Cannot reach the API (try restarting TV and pairing again)")

    def get(self,
            path: str,
            verbose=True,
            print_response: Literal[False, 1, 2] = 1,
            num_retries: int = None,
            retry_delay: float = 0,
            on_attempt_fail: Callable[[], Any] = None):
        """
        Sends a GET request.
        :raises: :class:`Pylips.Ex.ConnectionError` if `mqtt_listen == False` & no response.
        """
        max_retries = num_retries if num_retries else self.num_retries
        attempt = 1
        while attempt <= max_retries:
            eprint(f"\n> (GET attempt {attempt}/{max_retries})",
                   verbose=verbose)
            target = f"{self.config['TV']['protocol']}{self.config['TV']['host']}:{self.config['TV']['port']}/{self.config['TV']['apiv']}/{path}"
            eprint(f"Sending GET request to '{target}'…",
                   verbose=verbose)
            try:
                r = session.get(target,
                                verify=False,
                                auth=HTTPDigestAuth(str(self.config["TV"]["user"]), str(self.config["TV"]["pass"])),
                                timeout=self.timeout)
                eprint("Request SENT ✔",
                       verbose=verbose)
                if len(r.text.rstrip()) > 0:
                    response = r.text.rstrip()
                    if print_response == 1:
                        print(response)
                    elif print_response == 2:
                        eprint(response)
                    return response
            except Exception:
                eprint("Request FAILED ✘",
                       verbose=verbose)
            attempt += 1
            if on_attempt_fail:
                on_attempt_fail()
            if retry_delay and attempt <= max_retries:
                eprint(f"Waiting {retry_delay}s before retry…",
                       verbose=verbose)
                time.sleep(retry_delay)
        if self.config["DEFAULT"]["mqtt_listen"].lower() == "true":
            return self.mqtt_update_status({"powerstate": "Off", "volume": None, "muted": False, "cur_app": None, "ambilight": None, "ambihue": False})
        raise Pylips.Ex.ConnectionError("Cannot reach the API")

    def post(self,
             path: str,
             body: dict,
             verbose=True,
             update_mqtt=True,
             print_response: Literal[False, 1, 2] = 1,
             num_retries: int = None,
             retry_delay: float = 0,
             on_attempt_fail: Callable[[], Any] = None):
        """
        Sends a POST request.
        :raises: :class:`Pylips.Ex.ConnectionError` if `mqtt_listen == False` & no response.
        """
        max_retries = num_retries if num_retries else self.num_retries
        attempt = 1
        while attempt <= max_retries:
            eprint(f"\n> (POST attempt {attempt}/{max_retries})",
                   verbose=verbose)
            target = f"{self.config['TV']['protocol']}{self.config['TV']['host']}:{self.config['TV']['port']}/{self.config['TV']['apiv']}/{path}"
            eprint(f"Sending POST request to '{target}'…",
                   verbose=verbose)
            if type(body) is str:
                body = json.loads(body)
            try:
                r = session.post(target,
                                 json=body,
                                 verify=False,
                                 auth=HTTPDigestAuth(str(self.config["TV"]["user"]), str(self.config["TV"]["pass"])),
                                 timeout=self.timeout)
                eprint("Request SENT ✔",
                       verbose=verbose)
                if update_mqtt and self.config["DEFAULT"]["mqtt_listen"].lower() == "true" and len(sys.argv) == 1:
                    #  update status (only in MQTT mode)
                    self.mqtt_post_callback(path)
                if r.status_code == 200:
                    result = json.dumps({"response": "OK"}, indent=4)
                    if print_response == 1:
                        print(result)
                    elif print_response == 2:
                        eprint(result)
                    return result
                elif len(r.text.rstrip()) > 0:
                    response = r.text.rstrip()
                    if print_response == 1:
                        print(response)
                    elif print_response == 2:
                        eprint(response)
                    return response
            except Exception:
                eprint("Request FAILED ✘",
                       verbose=verbose)
            attempt += 1
            if on_attempt_fail:
                on_attempt_fail()
            if retry_delay and attempt <= max_retries:
                eprint(f"Waiting {retry_delay}s before retry…",
                       verbose=verbose)
                time.sleep(retry_delay)
        if self.config["DEFAULT"]["mqtt_listen"].lower() == "true" and len(sys.argv) == 1:
            return self.mqtt_update_status({"powerstate": "Off", "volume": None, "muted": False, "cur_app": None, "ambilight": None, "ambihue": False})
        raise Pylips.Ex.ConnectionError("Cannot reach the API")

    def run_command(self,
                    command: str,
                    body: dict = None,
                    verbose=True,
                    update_mqtt=True,
                    print_response: Literal[False, 1, 2] = 1,
                    num_retries: int = None,
                    retry_delay: float = 0,
                    on_attempt_fail: Callable[[], Any] = None):
        """
        Runs a command.
        :raises: :class:`Pylips.Ex.ConnectionError` if `mqtt_listen == False` & no response.
        """
        if command in self.available_commands["get"]:
            return self.get(self.available_commands["get"][command]["path"],
                            verbose=verbose,
                            print_response=print_response,
                            num_retries=num_retries,
                            retry_delay=retry_delay,
                            on_attempt_fail=on_attempt_fail)
        elif command in self.available_commands["post"]:
            if "body" in self.available_commands["post"][command] and body is None:
                if "input_" in command:
                    body = self.available_commands["post"]["google_assistant"]["body"]
                    path = self.available_commands["post"]["google_assistant"]["path"]
                    body["intent"]["extras"]["query"] = self.available_commands["post"][command]["body"]["query"]
                else:
                    body = self.available_commands["post"][command]["body"]
                    path = self.available_commands["post"][command]["path"]
                return self.post(path,
                                 body=body,
                                 verbose=verbose,
                                 update_mqtt=update_mqtt,
                                 print_response=print_response,
                                 num_retries=num_retries,
                                 retry_delay=retry_delay,
                                 on_attempt_fail=on_attempt_fail)
            if "body" in self.available_commands["post"][command] and body is not None:
                if type(body) is str:
                    body = json.loads(body)
                new_body = self.available_commands["post"][command]["body"]
                if command == "ambilight_brightness":
                    new_body["values"][0]["value"]["data"] = body
                elif command == "ambilight_color":
                    new_body["colorSettings"]["color"]["hue"] = int(body["hue"]*(255/360))
                    new_body["colorSettings"]["color"]["saturation"] = int(body["saturation"]*(255/100))
                    new_body["colorSettings"]["color"]["brightness"] = int(body["brightness"])
                elif command == "google_assistant":
                    new_body["intent"]["extras"]["query"] = body["query"]
                elif "input_" in command:
                    new_body = self.available_commands["google_assistant"][command]
                    new_body["intent"]["extras"]["query"] = self.available_commands["post"][command]["body"]["query"]
                return self.post(self.available_commands["post"][command]["path"],
                                 body=new_body,
                                 verbose=verbose,
                                 update_mqtt=update_mqtt,
                                 print_response=print_response,
                                 num_retries=num_retries,
                                 retry_delay=retry_delay,
                                 on_attempt_fail=on_attempt_fail)
            else:
                return self.post(self.available_commands["post"][command]["path"],
                                 body=body,
                                 verbose=verbose,
                                 update_mqtt=update_mqtt,
                                 print_response=print_response,
                                 num_retries=num_retries,
                                 retry_delay=retry_delay,
                                 on_attempt_fail=on_attempt_fail)
        elif command in self.available_commands["power"]:
            return session.post(f"http://{self.config['TV']['host']}:8008/{self.available_commands['power'][command]['path']}",
                                verify=False,
                                timeout=self.timeout)
        raise Pylips.Ex.ParamError("Unknown command: '" + command + "'")

    def mqtt_post_callback(self,
                           path: str):
        """
        Updates status immediately after sending a POST request.
        - Currently works only for ambilight and ambihue.
        """
        if "ambilight" or "ambihue" in path:
            self.mqtt_update_ambilight()
            self.mqtt_update_ambihue()

    def start_mqtt_listener(self):
        """
        Starts MQTT listener that accepts Pylips commands.
        """
        def on_connect(client, userdata, flags, rc):
            eprint("Connected to MQTT broker at", self.config["MQTT"]["host"])
            client.subscribe(self.config["MQTT"]["topic_pylips"])

        def on_message(client, userdata, msg):
            if str(msg.topic) == self.config["MQTT"]["topic_pylips"]:
                try:
                    message = json.loads(msg.payload.decode('utf-8'))
                except:
                    eprint("Invalid JSON in mqtt message:", msg.payload.decode('utf-8'))
                    return
            if "status" in message:
                self.mqtt_update_status(message["status"])
            if "command" in message:
                body = None
                path = ""
                if "body" in message:
                    body = message["body"]
                if "path" in message:
                    path = message["path"]
                if message["command"] == "get":
                    if len(path) == 0:
                        raise Pylips.Ex.ParamError("No '--path' arg specified")
                    self.get(path,
                             verbose=self.verbose,
                             print_response=False)
                elif message["command"] == "post":
                    if len(path) == 0:
                        raise Pylips.Ex.ParamError("No '--path' arg specified")
                    self.post(path,
                              body=body,
                              verbose=self.verbose)
                elif message["command"] != "post" and message["command"] != "get":
                    self.run_command(message["command"],
                                     body=body,
                                     verbose=self.verbose)

        self.mqtt = mqttc.Client()
        self.mqtt.on_connect = on_connect
        self.mqtt.on_message = on_message

        if len(self.config["MQTT"]["user"]) > 0 and len(self.config["MQTT"]["pass"]) > 0:
            self.mqtt.username_pw_set(self.config["MQTT"]["user"], self.config["MQTT"]["pass"])
        if self.config["MQTT"]["TLS"].lower() == "true":
            if len(self.config["MQTT"]["cert_path"].strip()) > 0:
                self.mqtt.tls_set(self.config["MQTT"]["cert_path"])
            else:
                self.mqtt.tls_set()
        self.mqtt.connect(str(self.config["MQTT"]["host"]), int(self.config["MQTT"]["port"]), 60)
        if self.config["DEFAULT"]["mqtt_listen"] == "True" and self.config["DEFAULT"]["mqtt_update"] == "False":
            self.mqtt.loop_forever()
        else:
            self.mqtt.loop_start()

    def mqtt_update_status(self, update):
        """
        Publishes an update with TV status over MQTT.
        """
        new_status = dict(self.last_status, **update)
        if json.dumps(new_status) != json.dumps(self.last_status):
            self.last_status = new_status
            self.mqtt.publish(str(self.config["MQTT"]["topic_status"]),
                              payload=json.dumps(self.last_status),
                              retain=True)

    def mqtt_update_powerstate(self):
        """
        Updates powerstate for MQTT status and returns `True` if TV is on.
        """
        powerstate_status = self.get("powerstate",
                                     verbose=self.verbose,
                                     print_response=False)
        if powerstate_status is not None and powerstate_status[0] == '{':
            powerstate_status = json.loads(powerstate_status)
            if "powerstate" in powerstate_status:
                if "powerstate" in self.last_status and self.last_status["powerstate"] != powerstate_status['powerstate']:
                    self.mqtt.publish(str(self.config["MQTT"]["topic_pylips"]),
                                      payload=json.dumps({"status": {"powerstate": powerstate_status['powerstate']}}),
                                      retain=False)
                if powerstate_status['powerstate'].lower() == "on":
                    return True
            else:
                self.mqtt_update_status({"powerstate": "Off", "volume": None, "muted": False, "cur_app": None, "ambilight": None, "ambihue": False})
        else:
            self.mqtt_update_status({"powerstate": "Off", "volume": None, "muted": False, "cur_app": None, "ambilight": None, "ambihue": False})
        return False

    def mqtt_update_ambilight(self):
        """
        Updates ambilight for MQTT status.
        """
        ambilight_status = self.get("ambilight/currentconfiguration",
                                    verbose=self.verbose,
                                    print_response=False)
        if ambilight_status is not None and ambilight_status[0] == '{':
            ambilight_status = json.loads(ambilight_status)
            if "styleName" in ambilight_status:
                ambilight = ambilight_status
                if json.dumps(self.last_status["ambilight"]) != json.dumps(ambilight):
                    self.mqtt.publish(str(self.config["MQTT"]["topic_pylips"]),
                                      payload=json.dumps({"status": {"ambilight": ambilight}}),
                                      retain=False)

    def mqtt_update_ambihue(self):
        """
        Updates ambihue for MQTT status.
        """
        ambihue_status = self.run_command("ambihue_status",
                                          verbose=self.verbose,
                                          update_mqtt=False,
                                          print_response=False)
        if ambihue_status is not None and ambihue_status[0] == '{':
            ambihue_status = json.loads(ambihue_status)
            if "power" in ambihue_status:
                ambihue = ambihue_status["power"]
                if self.last_status["ambihue"] != ambihue:
                    self.mqtt.publish(str(self.config["MQTT"]["topic_pylips"]),
                                      payload=json.dumps({"status": {"ambihue": ambihue}}),
                                      retain=False)

    def mqtt_update_app(self):
        """
        Updates current app for MQTT status.
        """
        actv_status = self.run_command("current_app",
                                       verbose=self.verbose,
                                       update_mqtt=False,
                                       print_response=False)
        if actv_status is not None and actv_status[0] == '{':
            actv_status = json.loads(actv_status)
            if "component" in actv_status:
                if actv_status["component"]["packageName"] == "org.droidtv.zapster" or actv_status["component"]["packageName"] == "NA":
                    self.mqtt_update_channel()
                else:
                    if self.last_status["cur_app"] is None or self.last_status["cur_app"] != actv_status["component"]["packageName"]:
                        self.mqtt.publish(str(self.config["MQTT"]["topic_pylips"]),
                                          payload=json.dumps({"status": {"cur_app": actv_status["component"]["packageName"]}}),
                                          retain=False)

    def mqtt_update_channel(self):
        """
        Updates current channel for MQTT status.
        """
        channel = self.run_command("current_channel",
                                   verbose=self.verbose,
                                   update_mqtt=False)
        if channel is not None and channel[0] == '{':
            channel = json.loads(channel)
            if "channel" in channel:
                if json.dumps(self.last_status["cur_app"]) != json.dumps({"app": "TV", "channel": channel}):
                    self.mqtt.publish(str(self.config["MQTT"]["topic_pylips"]),
                                      payload=json.dumps({"status": {"cur_app": {"app": "TV", "channel": channel}}}),
                                      retain=False)

    def mqtt_update_volume(self):
        """
        Updates volume and mute state for MQTT status.
        """
        vol_status = self.run_command("volume",
                                      verbose=self.verbose,
                                      update_mqtt=False,
                                      print_response=False)
        if vol_status is not None:
            vol_status = json.loads(vol_status)
            if "muted" in vol_status:
                muted = vol_status["muted"]
                volume = vol_status["current"]
                if self.last_status["muted"] != muted or self.last_status["volume"] != volume:
                    self.mqtt.publish(str(self.config["MQTT"]["topic_pylips"]),
                                      payload=json.dumps({"status": {"muted": muted, "volume": volume}}),
                                      retain=False)

    def start_mqtt_updater(self, verbose=True):
        """
        Runs MQTT update functions with a specified update interval.
        """
        eprint("Started MQTT status updater",
               verbose=verbose)
        while True:
            if self.mqtt_update_powerstate():
                self.mqtt_update_volume()
                self.mqtt_update_app()
                self.mqtt_update_ambilight()
                self.mqtt_update_ambihue()
            time.sleep(int(self.config["DEFAULT"]["update_interval"]))


if __name__ == '__main__':
    try:
        Pylips(args.config)
    except (Pylips.Ex.ConfigError,
            Pylips.Ex.ParamError,
            Pylips.Ex.ConnectionError,
            Pylips.Ex.PairingError) as e:
        if type(e) in [Pylips.Ex.ConnectionError, Pylips.Ex.PairingError]:
            print(json.dumps({"error": str(e)}, indent=4))
        eprint(e)
        exit(1)
