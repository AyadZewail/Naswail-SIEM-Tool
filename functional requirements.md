## Home Module (Revised SRS Functional Requirements)

---

### FR-Home-01

| Field                                       | Content                                                                                                                                                                                                                                                                             |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-01                                                                                                                                                                                                                                                                          |
| Module Name                                 | Home – System Startup                                                                                                                                                                                                                                                               |
| Detailed Functional Requirement Description | The system shall provide a graphical desktop interface that initializes all monitoring, analysis, and response services during application startup. Users shall be informed of the initialization progress through a loading interface before the main dashboard becomes available. |
| Priority                                    | Must Have                                                                                                                                                                                                                                                                           |

---

### FR-Home-02

| Field                                       | Content                                                                                                                                                                                                                                           |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-02                                                                                                                                                                                                                                        |
| Module Name                                 | Home – Live Network Traffic Acquisition                                                                                                                                                                                                           |
| Detailed Functional Requirement Description | The system shall capture network traffic from a selected network interface in real time and make the captured packets available for monitoring, analysis, anomaly detection, visualization, and storage throughout the active monitoring session. |
| Priority                                    | Must Have                                                                                                                                                                                                                                         |

---

### FR-Home-03

| Field                                       | Content                                                                                                                                                                                                                                                                              |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Requirement ID                              | FR-Home-03                                                                                                                                                                                                                                                                           |
| Module Name                                 | Home – Packet Capture File Import                                                                                                                                                                                                                                                    |
| Detailed Functional Requirement Description | The system shall allow users to import previously captured network traffic from packet capture files. Upon import, the system shall process the imported traffic as a new monitoring session and update all relevant monitoring, analysis, and visualization components accordingly. |
| Priority                                    | Must Have                                                                                                                                                                                                                                                                            |

---

### FR-Home-04

| Field                                       | Content                                                                                                                                                                                                                                  |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-04                                                                                                                                                                                                                               |
| Module Name                                 | Home – CSV Traffic Import                                                                                                                                                                                                                |
| Detailed Functional Requirement Description | The system shall allow users to import network traffic data stored in supported tabular formats and process the imported records as network traffic events. The system shall notify the user when unsupported file formats are provided. |
| Priority                                    | Should Have                                                                                                                                                                                                                              |

---

### FR-Home-05

| Field                                       | Content                                                                                                                                                                                                                                                                                              |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-05                                                                                                                                                                                                                                                                                           |
| Module Name                                 | Home – Packet Storage Management                                                                                                                                                                                                                                                                     |
| Detailed Functional Requirement Description | The system shall maintain an internal repository of captured and processed packets for use by monitoring, filtering, analysis, visualization, and incident response functions. When storage limits are reached, the system shall automatically manage older records to preserve continued operation. |
| Priority                                    | Must Have                                                                                                                                                                                                                                                                                            |

---

### FR-Home-06

| Field                                       | Content                                                                                                                                                                                                                                                               |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-06                                                                                                                                                                                                                                                            |
| Module Name                                 | Home – Packet Processing                                                                                                                                                                                                                                              |
| Detailed Functional Requirement Description | The system shall process captured traffic and extract relevant network information, including addressing, protocol, communication endpoint, and traffic characteristics. The extracted information shall be made available to all monitoring and analysis components. |
| Priority                                    | Must Have                                                                                                                                                                                                                                                             |

---

### FR-Home-07

| Field                                       | Content                                                                                                                                                                                                                                                     |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-07                                                                                                                                                                                                                                                  |
| Module Name                                 | Home – Packet Monitoring Interface                                                                                                                                                                                                                          |
| Detailed Functional Requirement Description | The system shall present processed network traffic in a tabular format and visually distinguish traffic categories such as normal traffic, suspicious traffic, blocked traffic, corrupted packets, and protocol-specific traffic through visual indicators. |
| Priority                                    | Must Have                                                                                                                                                                                                                                                   |

---

### FR-Home-08

| Field                                       | Content                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-08                                                                                                                                                                                                                                                                                                           |
| Module Name                                 | Home – Packet Filtering                                                                                                                                                                                                                                                                                              |
| Detailed Functional Requirement Description | The system shall allow users to filter captured traffic using multiple criteria including network protocols, source and destination addresses, communication ports, time ranges, traffic direction, and sensor-related attributes. Filtered results shall be displayed independently of the complete packet dataset. |
| Priority                                    | Must Have                                                                                                                                                                                                                                                                                                            |

---

### FR-Home-09

| Field                                       | Content                                                                                                                                                                                                      |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Requirement ID                              | FR-Home-09                                                                                                                                                                                                   |
| Module Name                                 | Home – Packet Detail Inspection                                                                                                                                                                              |
| Detailed Functional Requirement Description | The system shall allow users to inspect detailed information about any displayed packet, including protocol-layer information and packet metadata, to support traffic analysis and investigation activities. |
| Priority                                    | Must Have                                                                                                                                                                                                    |

---

### FR-Home-10

| Field                                       | Content                                                                                                                                         |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-10                                                                                                                                      |
| Module Name                                 | Home – Packet Data Decoding                                                                                                                     |
| Detailed Functional Requirement Description | The system shall provide a decoded representation of packet contents to enable examination of the underlying packet structure and payload data. |
| Priority                                    | Should Have                                                                                                                                     |

---

### FR-Home-11

| Field                                       | Content                                                                                                                                                                                                                                   |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-11                                                                                                                                                                                                                                |
| Module Name                                 | Home – Protocol Identification                                                                                                                                                                                                            |
| Detailed Functional Requirement Description | The system shall identify the protocols associated with captured network traffic and classify packets according to their communication type in order to support monitoring, filtering, visualization, and statistical analysis functions. |
| Priority                                    | Must Have                                                                                                                                                                                                                                 |

---

### FR-Home-12

| Field                                       | Content                                                                                                                                                                                               |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-12                                                                                                                                                                                            |
| Module Name                                 | Home – Packet Integrity Verification                                                                                                                                                                  |
| Detailed Functional Requirement Description | The system shall verify the integrity of captured packets and identify packets that appear corrupted or malformed. Detected packets shall be recorded and visually distinguished from normal traffic. |
| Priority                                    | Must Have                                                                                                                                                                                             |

---

### FR-Home-13

| Field                                       | Content                                                                                                                                                                                        |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-13                                                                                                                                                                                     |
| Module Name                                 | Home – Traffic Statistics                                                                                                                                                                      |
| Detailed Functional Requirement Description | The system shall generate statistical summaries of monitored traffic, including protocol distributions and descriptive traffic metrics, to support network monitoring and analysis activities. |
| Priority                                    | Should Have                                                                                                                                                                                    |

---

### FR-Home-14

| Field                                       | Content                                                                                                                                                                                 |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-14                                                                                                                                                                              |
| Module Name                                 | Home – Signature-Based Anomaly Detection                                                                                                                                                |
| Detailed Functional Requirement Description | The system shall detect suspicious network activity using rule-based intrusion detection mechanisms and associate detected events with known attack classifications whenever available. |
| Priority                                    | Must Have                                                                                                                                                                               |

---

### FR-Home-15

| Field                                       | Content                                                                                                                                                                                          |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Requirement ID                              | FR-Home-15                                                                                                                                                                                       |
| Module Name                                 | Home – Machine Learning Anomaly Detection                                                                                                                                                        |
| Detailed Functional Requirement Description | The system shall support the integration of external machine-learning-based intrusion detection services and incorporate the resulting anomaly information into the overall monitoring workflow. |
| Priority                                    | Should Have                                                                                                                                                                                      |

---

### FR-Home-16

| Field                                       | Content                                                                                                                                                                                                                               |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-16                                                                                                                                                                                                                            |
| Module Name                                 | Home – Anomaly Monitoring                                                                                                                                                                                                             |
| Detailed Functional Requirement Description | The system shall maintain a dedicated view of detected anomalies containing relevant information such as event time, communication endpoints, and detected attack classification. Duplicate events shall not be repeatedly displayed. |
| Priority                                    | Must Have                                                                                                                                                                                                                             |

---

### FR-Home-17

| Field                                       | Content                                                                                                                                                                                                       |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-17                                                                                                                                                                                                    |
| Module Name                                 | Home – Activity Logging                                                                                                                                                                                       |
| Detailed Functional Requirement Description | The system shall maintain a chronological log of significant monitoring and security events, including detected anomalies, traffic-control actions, and operational alerts generated during system execution. |
| Priority                                    | Must Have                                                                                                                                                                                                     |

---

### FR-Home-18

| Field                                       | Content                                                                                                              |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-18                                                                                                           |
| Module Name                                 | Home – Log Export                                                                                                    |
| Detailed Functional Requirement Description | The system shall allow users to export recorded activity logs for archival, reporting, or further analysis purposes. |
| Priority                                    | Could Have                                                                                                           |

---

### FR-Home-19

| Field                                       | Content                                                                                                                                       |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-19                                                                                                                                    |
| Module Name                                 | Home – Blacklist Management                                                                                                                   |
| Detailed Functional Requirement Description | The system shall allow users to maintain a list of blocked network addresses and shall provide visibility into all currently blocked entries. |
| Priority                                    | Must Have                                                                                                                                     |

---

### FR-Home-20

| Field                                       | Content                                                                                                                                                                                                     |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-20                                                                                                                                                                                                  |
| Module Name                                 | Home – Network Access Control                                                                                                                                                                               |
| Detailed Functional Requirement Description | The system shall enforce network access-control actions by applying operating-system-level blocking rules to user-specified network addresses and shall support removal of previously applied restrictions. |
| Priority                                    | Must Have                                                                                                                                                                                                   |

---

### FR-Home-21

| Field                                       | Content                                                                                                                                                                      |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-21                                                                                                                                                                   |
| Module Name                                 | Home – Sensor Management                                                                                                                                                     |
| Detailed Functional Requirement Description | The system shall allow users to register, view, and remove network sensors used for monitoring specific devices or communication endpoints within the monitored environment. |
| Priority                                    | Should Have                                                                                                                                                                  |

---

### FR-Home-22

| Field                                       | Content                                                                                                                                                                                             |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-22                                                                                                                                                                                          |
| Module Name                                 | Home – Sensor-Based Monitoring                                                                                                                                                                      |
| Detailed Functional Requirement Description | The system shall allow users to view traffic associated with registered sensors and shall provide filtering capabilities that focus monitoring activities on selected sensors or groups of sensors. |
| Priority                                    | Should Have                                                                                                                                                                                         |

---

### FR-Home-23

| Field                                       | Content                                                                                                                                                                                                                  |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Requirement ID                              | FR-Home-23                                                                                                                                                                                                               |
| Module Name                                 | Home – Application Monitoring                                                                                                                                                                                            |
| Detailed Functional Requirement Description | The system shall display information about active applications that are generating or receiving network traffic, including resource utilization and communication information relevant to network monitoring activities. |
| Priority                                    | Should Have                                                                                                                                                                                                              |

---

### FR-Home-24

| Field                                       | Content                                                                                                                                                                      |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-24                                                                                                                                                                   |
| Module Name                                 | Home – Application-Based Traffic Filtering                                                                                                                                   |
| Detailed Functional Requirement Description | The system shall allow users to isolate and inspect network traffic associated with a selected application in order to support investigation and troubleshooting activities. |
| Priority                                    | Could Have                                                                                                                                                                   |

---

### FR-Home-25

| Field                                       | Content                                                                                                                                                     |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-25                                                                                                                                                  |
| Module Name                                 | Home – Packet Export                                                                                                                                        |
| Detailed Functional Requirement Description | The system shall allow users to export captured network traffic to packet capture files for external analysis, archival, or evidence preservation purposes. |
| Priority                                    | Should Have                                                                                                                                                 |

---

### FR-Home-26

| Field                                       | Content                                                                                                                                     |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-26                                                                                                                                  |
| Module Name                                 | Home – Packet Generation                                                                                                                    |
| Detailed Functional Requirement Description | The system shall allow users to generate and transmit custom network packets for testing, simulation, and network experimentation purposes. |
| Priority                                    | Won't Have                                                                                                                                  |

---

### FR-Home-27

| Field                                       | Content                                                                                                                                          |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Requirement ID                              | FR-Home-27                                                                                                                                       |
| Module Name                                 | Home – Traffic Rate Monitoring                                                                                                                   |
| Detailed Functional Requirement Description | The system shall continuously monitor and display network traffic rates in real time and provide visual indicators of current traffic intensity. |
| Priority                                    | Should Have                                                                                                                                      |

---

### FR-Home-28

| Field                                       | Content                                                                                                                                         |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-28                                                                                                                                      |
| Module Name                                 | Home – Sensor Visualization                                                                                                                     |
| Detailed Functional Requirement Description | The system shall provide graphical representations of registered sensor information to support situational awareness and monitoring activities. |
| Priority                                    | Could Have                                                                                                                                      |

---

### FR-Home-29

| Field                                       | Content                                                                                                                                                           |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-29                                                                                                                                                        |
| Module Name                                 | Home – Traffic Capture Sessions                                                                                                                                   |
| Detailed Functional Requirement Description | The system shall allow users to initiate and terminate packet capture sessions and shall maintain captured traffic for subsequent analysis and export operations. |
| Priority                                    | Should Have                                                                                                                                                       |

---

### FR-Home-30

| Field                                       | Content                                                                                                                                                           |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-30                                                                                                                                                        |
| Module Name                                 | Home – Live Monitoring Restoration                                                                                                                                |
| Detailed Functional Requirement Description | The system shall allow users to terminate imported monitoring sessions and restore real-time traffic monitoring while resetting session-specific monitoring data. |
| Priority                                    | Must Have                                                                                                                                                         |

---

### FR-Home-31

| Field                                       | Content                                                                                                                                                        |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-31                                                                                                                                                     |
| Module Name                                 | Home – Filter Reset                                                                                                                                            |
| Detailed Functional Requirement Description | The system shall provide users with the ability to remove all active filters and restore the default monitoring view containing all available traffic records. |
| Priority                                    | Should Have                                                                                                                                                    |

---

### FR-Home-32

| Field                                       | Content                                                                                                                                                                              |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Requirement ID                              | FR-Home-32                                                                                                                                                                           |
| Module Name                                 | Home – Traffic Classification                                                                                                                                                        |
| Detailed Functional Requirement Description | The system shall classify monitored traffic according to whether communications originate from internal or external network sources and shall maintain statistics for each category. |
| Priority                                    | Should Have                                                                                                                                                                          |

---

### FR-Home-33

| Field                                       | Content                                                                                                                                                       |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-33                                                                                                                                                    |
| Module Name                                 | Home – Blocked Traffic Monitoring                                                                                                                             |
| Detailed Functional Requirement Description | The system shall identify traffic affected by configured security controls and shall clearly indicate blocked communications within the monitoring interface. |
| Priority                                    | Must Have                                                                                                                                                     |

---

### FR-Home-34

| Field                                       | Content                                                                                                                                                                       |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-34                                                                                                                                                                    |
| Module Name                                 | Home – Intrusion Detection Service Initialization                                                                                                                             |
| Detailed Functional Requirement Description | The system shall support automatic initialization of integrated intrusion detection services when the required operating-system permissions and configurations are available. |
| Priority                                    | Should Have                                                                                                                                                                   |

---

### FR-Home-35

| Field                                       | Content                                                                                                                                                      |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Requirement ID                              | FR-Home-35                                                                                                                                                   |
| Module Name                                 | Home – Module Navigation                                                                                                                                     |
| Detailed Functional Requirement Description | The system shall allow users to navigate between the Home, Analysis, Tools, and Incident Response modules without terminating the active monitoring session. |
| Priority                                    | Must Have                                                                                                                                                    |

---

### FR-Home-36

| Field                                       | Content                                                                                                                                                                                                                 |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-36                                                                                                                                                                                                              |
| Module Name                                 | Home – Notifications                                                                                                                                                                                                    |
| Detailed Functional Requirement Description | The system shall provide an in-application notification mechanism capable of presenting security alerts, operational messages, and informational events together with their associated severity and contextual details. |
| Priority                                    | Could Have                                                                                                                                                                                                              |

---

### FR-Home-37

| Field                                       | Content                                                                                                                                                                            |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Home-37                                                                                                                                                                         |
| Module Name                                 | Home – Shared Information Management                                                                                                                                               |
| Detailed Functional Requirement Description | The system shall maintain a centralized repository of monitoring, analysis, anomaly, logging, and response information to ensure consistent data sharing among all system modules. |
| Priority                                    | Must Have                                                                                                                                                                          |

---

# Incident Response Module (Revised SRS Functional Requirements)

---

### FR-IR-01

| Field                                       | Content                                                                                                                                                                                                                                                                                                       |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-01                                                                                                                                                                                                                                                                                                      |
| Module Name                                 | Incident Response – Anomaly Management                                                                                                                                                                                                                                                                        |
| Detailed Functional Requirement Description | The system shall present detected security incidents and anomalous network activities within the Incident Response module, including relevant communication and attack information required to support investigation and mitigation activities. Duplicate incident records shall not be repeatedly displayed. |
| Priority                                    | Must Have                                                                                                                                                                                                                                                                                                     |

---

### FR-IR-02

| Field                                       | Content                                                                                                                                                                                                                                                                                                |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Requirement ID                              | FR-IR-02                                                                                                                                                                                                                                                                                               |
| Module Name                                 | Incident Response – Threat Intelligence Collection                                                                                                                                                                                                                                                     |
| Detailed Functional Requirement Description | The system shall gather threat intelligence information related to detected attacks in order to assist users in understanding the nature, impact, and potential mitigation strategies associated with a security incident. Threat intelligence collection shall not interrupt normal system operation. |
| Priority                                    | Must Have                                                                                                                                                                                                                                                                                              |

---

### FR-IR-03

| Field                                       | Content                                                                                                                                                                                                                                                                |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-03                                                                                                                                                                                                                                                               |
| Module Name                                 | Incident Response – Mitigation Recommendation Generation                                                                                                                                                                                                               |
| Detailed Functional Requirement Description | The system shall analyze collected threat intelligence information and generate mitigation recommendations that can assist in responding to detected attacks. Recommendations shall be derived from the most relevant information available for the selected incident. |
| Priority                                    | Must Have                                                                                                                                                                                                                                                              |

---

### FR-IR-04

| Field                                       | Content                                                                                                                                                                                                                           |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-04                                                                                                                                                                                                                          |
| Module Name                                 | Incident Response – Automated Decision Support                                                                                                                                                                                    |
| Detailed Functional Requirement Description | The system shall support automated evaluation of mitigation recommendations and determine an appropriate response action based on the characteristics of the detected incident and the available threat intelligence information. |
| Priority                                    | Must Have                                                                                                                                                                                                                         |

---

### FR-IR-05

| Field                                       | Content                                                                                                                                                                                                     |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-05                                                                                                                                                                                                    |
| Module Name                                 | Incident Response – Automated Mitigation                                                                                                                                                                    |
| Detailed Functional Requirement Description | The system shall be capable of automatically executing approved mitigation actions in response to detected threats. Executed actions and their outcomes shall be recorded for auditing and review purposes. |
| Priority                                    | Must Have                                                                                                                                                                                                   |

---

### FR-IR-06

| Field                                       | Content                                                                                                                                                                                                             |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-06                                                                                                                                                                                                            |
| Module Name                                 | Incident Response – IP Address Blocking                                                                                                                                                                             |
| Detailed Functional Requirement Description | The system shall allow users to block or unblock network addresses associated with malicious or suspicious activity and shall ensure that changes are reflected throughout the monitoring and response environment. |
| Priority                                    | Must Have                                                                                                                                                                                                           |

---

### FR-IR-07

| Field                                       | Content                                                                                                                                                                                                 |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-07                                                                                                                                                                                                |
| Module Name                                 | Incident Response – Port Access Control                                                                                                                                                                 |
| Detailed Functional Requirement Description | The system shall allow users to block or unblock communication ports in order to restrict unwanted or malicious network activity. The current status of controlled ports shall be available for review. |
| Priority                                    | Must Have                                                                                                                                                                                               |

---

### FR-IR-08

| Field                                       | Content                                                                                                                                                                             |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-08                                                                                                                                                                            |
| Module Name                                 | Incident Response – Traffic Rate Limiting                                                                                                                                           |
| Detailed Functional Requirement Description | The system shall allow users to apply traffic rate limits to selected communication endpoints in order to reduce the impact of excessive or potentially malicious network activity. |
| Priority                                    | Should Have                                                                                                                                                                         |

---

### FR-IR-09

| Field                                       | Content                                                                                                                                                       |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-09                                                                                                                                                      |
| Module Name                                 | Incident Response – Rate Limiting Management                                                                                                                  |
| Detailed Functional Requirement Description | The system shall allow users to modify or remove previously applied traffic rate limits and shall maintain visibility into all active rate-limiting controls. |
| Priority                                    | Should Have                                                                                                                                                   |

---

### FR-IR-10

| Field                                       | Content                                                                                                                                                           |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-10                                                                                                                                                          |
| Module Name                                 | Incident Response – Process Termination                                                                                                                           |
| Detailed Functional Requirement Description | The system shall allow users to terminate processes that are suspected of participating in malicious activity in order to contain or mitigate security incidents. |
| Priority                                    | Should Have                                                                                                                                                       |

---

### FR-IR-11

| Field                                       | Content                                                                                                                                                                                            |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-11                                                                                                                                                                                           |
| Module Name                                 | Incident Response – Distributed Process Containment                                                                                                                                                |
| Detailed Functional Requirement Description | The system shall support coordinated process-containment actions across multiple hosts by distributing process-termination instructions to participating systems within the monitored environment. |
| Priority                                    | Could Have                                                                                                                                                                                         |

---

### FR-IR-12

| Field                                       | Content                                                                                                                                                                                                                   |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-12                                                                                                                                                                                                                  |
| Module Name                                 | Incident Response – Payload Analysis                                                                                                                                                                                      |
| Detailed Functional Requirement Description | The system shall analyze suspicious network payloads using multiple decoding and interpretation techniques in order to reveal potentially hidden, encoded, or obfuscated content that may assist incident investigations. |
| Priority                                    | Should Have                                                                                                                                                                                                               |

---

### FR-IR-13

| Field                                       | Content                                                                                                                                                                 |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-13                                                                                                                                                                |
| Module Name                                 | Incident Response – Attack Origin Identification                                                                                                                        |
| Detailed Functional Requirement Description | The system shall determine and display the geographical origin of network communications associated with detected incidents whenever location information is available. |
| Priority                                    | Should Have                                                                                                                                                             |

---

### FR-IR-14

| Field                                       | Content                                                                                                                                                                                                                                                                  |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Requirement ID                              | FR-IR-14                                                                                                                                                                                                                                                                 |
| Module Name                                 | Incident Response – Incident Logging                                                                                                                                                                                                                                     |
| Detailed Functional Requirement Description | The system shall maintain a detailed record of incident-response activities, including incident identification, intelligence collection, decision-making activities, mitigation actions, and response outcomes, in order to support auditing and post-incident analysis. |
| Priority                                    | Must Have                                                                                                                                                                                                                                                                |

---

### FR-IR-15

| Field                                       | Content                                                                                                                                                                                                                      |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-15                                                                                                                                                                                                                     |
| Module Name                                 | Incident Response – Incident Intelligence Display                                                                                                                                                                            |
| Detailed Functional Requirement Description | The system shall present detailed information associated with a selected incident, including attack characteristics, threat intelligence findings, decoded content, origin information, and recommended mitigation guidance. |
| Priority                                    | Must Have                                                                                                                                                                                                                    |

---

### FR-IR-16

| Field                                       | Content                                                                                                                                                                                      |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-16                                                                                                                                                                                     |
| Module Name                                 | Incident Response – Response Time Measurement                                                                                                                                                |
| Detailed Functional Requirement Description | The system shall measure and record the time required to perform incident-response activities in order to support performance evaluation and operational assessment of the response process. |
| Priority                                    | Should Have                                                                                                                                                                                  |

---

### FR-IR-17

| Field                                       | Content                                                                                                                                                                                                 |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-17                                                                                                                                                                                                |
| Module Name                                 | Incident Response – Incident Synchronization                                                                                                                                                            |
| Detailed Functional Requirement Description | The Incident Response module shall continuously synchronize with the system's anomaly detection components to ensure that newly detected incidents are made available for investigation and mitigation. |
| Priority                                    | Must Have                                                                                                                                                                                               |

---

### FR-IR-18

| Field                                       | Content                                                                                                                                                                   |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-IR-18                                                                                                                                                                  |
| Module Name                                 | Incident Response – Module Navigation                                                                                                                                     |
| Detailed Functional Requirement Description | The system shall allow users to navigate between the Incident Response, Home, Analysis, and Tools modules without interrupting ongoing monitoring or response activities. |
| Priority                                    | Must Have                                                                                                                                                                 |

---

# Tools Module (Revised SRS Functional Requirements)

---

### FR-Tool-01

| Field                                       | Content                                                                                                                                                                                                                                                                          |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Tool-01                                                                                                                                                                                                                                                                       |
| Module Name                                 | Tools – Network Activity Extraction                                                                                                                                                                                                                                              |
| Detailed Functional Requirement Description | The system shall analyze captured network traffic and identify user and device activities represented within the monitored communications. Extracted activities shall include information that assists users in understanding network usage patterns and communication behavior. |
| Priority                                    | Should Have                                                                                                                                                                                                                                                                      |

---

### FR-Tool-02

| Field                                       | Content                                                                                                                                                                                          |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Requirement ID                              | FR-Tool-02                                                                                                                                                                                       |
| Module Name                                 | Tools – Network Activity Monitoring                                                                                                                                                              |
| Detailed Functional Requirement Description | The system shall present extracted network activities through a dedicated interface that allows users to review, inspect, and monitor observed activity records generated from captured traffic. |
| Priority                                    | Should Have                                                                                                                                                                                      |

---

### FR-Tool-03

| Field                                       | Content                                                                                                                                                     |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Tool-03                                                                                                                                                  |
| Module Name                                 | Tools – Activity Export                                                                                                                                     |
| Detailed Functional Requirement Description | The system shall allow users to export recorded network activity information for documentation, reporting, archival, or further external analysis purposes. |
| Priority                                    | Could Have                                                                                                                                                  |

---

### FR-Tool-04

| Field                                       | Content                                                                                                                                                                                 |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Tool-04                                                                                                                                                                              |
| Module Name                                 | Tools – Traffic Prediction Model Generation                                                                                                                                             |
| Detailed Functional Requirement Description | The system shall analyze historical network traffic patterns and generate predictive models capable of estimating future traffic behavior based on previously observed monitoring data. |
| Priority                                    | Should Have                                                                                                                                                                             |

---

### FR-Tool-05

| Field                                       | Content                                                                                                                                                                                                             |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Tool-05                                                                                                                                                                                                          |
| Module Name                                 | Tools – Traffic Forecasting                                                                                                                                                                                         |
| Detailed Functional Requirement Description | The system shall provide traffic forecasts for future time periods and present estimated traffic levels to assist users in anticipating network conditions and identifying potential capacity or security concerns. |
| Priority                                    | Should Have                                                                                                                                                                                                         |

---

### FR-Tool-06

| Field                                       | Content                                                                                                                                                                                  |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Tool-06                                                                                                                                                                               |
| Module Name                                 | Tools – Predictive Visualization                                                                                                                                                         |
| Detailed Functional Requirement Description | The system shall provide graphical visualizations of predicted network traffic trends and associated prediction information to facilitate interpretation of forecasted network behavior. |
| Priority                                    | Could Have                                                                                                                                                                               |

---

### FR-Tool-07

| Field                                       | Content                                                                                                                                                                                      |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Tool-07                                                                                                                                                                                   |
| Module Name                                 | Tools – Corrupted Traffic Analysis                                                                                                                                                           |
| Detailed Functional Requirement Description | The system shall provide a dedicated view of packets identified as corrupted or malformed in order to support network troubleshooting, forensic analysis, and data integrity investigations. |
| Priority                                    | Should Have                                                                                                                                                                                  |

---

### FR-Tool-08

| Field                                       | Content                                                                                                                                                                     |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Tool-08                                                                                                                                                                  |
| Module Name                                 | Tools – Forecast Configuration                                                                                                                                              |
| Detailed Functional Requirement Description | The system shall allow users to specify the forecasting period used for traffic prediction and shall generate prediction results based on the selected forecasting horizon. |
| Priority                                    | Could Have                                                                                                                                                                  |

---

### FR-Tool-09

| Field                                       | Content                                                                                                                                                                              |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Requirement ID                              | FR-Tool-09                                                                                                                                                                           |
| Module Name                                 | Tools – Module Navigation                                                                                                                                                            |
| Detailed Functional Requirement Description | The system shall allow users to navigate between the Tools, Home, Analysis, and Incident Response modules without interrupting ongoing monitoring, analysis, or response activities. |
| Priority                                    | Must Have                                                                                                                                                                            |

---

# Analysis Module (Revised SRS Functional Requirements)

---

### FR-Analysis-01

| Field                                       | Content                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Analysis-01                                                                                                                                                                                                                                                                                                       |
| Module Name                                 | Analysis – Network Topology Visualization                                                                                                                                                                                                                                                                            |
| Detailed Functional Requirement Description | The system shall generate a visual representation of the monitored network topology by identifying communicating devices and the relationships between them. The visualization shall assist users in understanding network structure, communication paths, and device interactions within the monitored environment. |
| Priority                                    | Must Have                                                                                                                                                                                                                                                                                                            |

---

### FR-Analysis-02

| Field                                       | Content                                                                                                                                                                                                                                    |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Requirement ID                              | FR-Analysis-02                                                                                                                                                                                                                             |
| Module Name                                 | Analysis – Distribution Analysis                                                                                                                                                                                                           |
| Detailed Functional Requirement Description | The system shall provide graphical analysis of network traffic distributions, including traffic classifications, protocol usage, and sensor-related activity, in order to support traffic pattern identification and comparative analysis. |
| Priority                                    | Should Have                                                                                                                                                                                                                                |

---

### FR-Analysis-03

| Field                                       | Content                                                                                                                                                                                                |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Requirement ID                              | FR-Analysis-03                                                                                                                                                                                         |
| Module Name                                 | Analysis – Trend Analysis                                                                                                                                                                              |
| Detailed Functional Requirement Description | The system shall provide graphical representations of network traffic trends over time, allowing users to observe changes in network behavior, protocol activity, sensor activity, and traffic volume. |
| Priority                                    | Should Have                                                                                                                                                                                            |

---

### FR-Analysis-04

| Field                                       | Content                                                                                                                                                                                                    |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Analysis-04                                                                                                                                                                                             |
| Module Name                                 | Analysis – Time-Series Analysis                                                                                                                                                                            |
| Detailed Functional Requirement Description | The system shall provide time-based visual analysis of monitored network activity to assist users in identifying temporal patterns, fluctuations, and behavioral changes within the monitored environment. |
| Priority                                    | Should Have                                                                                                                                                                                                |

---

### FR-Analysis-05

| Field                                       | Content                                                                                                                                                                     |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Analysis-05                                                                                                                                                              |
| Module Name                                 | Analysis – Heatmap Visualization                                                                                                                                            |
| Detailed Functional Requirement Description | The system shall provide heatmap-based visualizations of network activity in order to highlight concentrations, variations, and patterns within monitored traffic datasets. |
| Priority                                    | Could Have                                                                                                                                                                  |

---

### FR-Analysis-06

| Field                                       | Content                                                                                                                                                                                                         |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Analysis-06                                                                                                                                                                                                  |
| Module Name                                 | Analysis – Proportional Traffic Analysis                                                                                                                                                                        |
| Detailed Functional Requirement Description | The system shall provide visual representations of proportional relationships within monitored traffic data, enabling users to compare the relative contribution of protocols, sensors, and traffic categories. |
| Priority                                    | Should Have                                                                                                                                                                                                     |

---

### FR-Analysis-07

| Field                                       | Content                                                                                                                                                                                                                                                                                                     |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Analysis-07                                                                                                                                                                                                                                                                                              |
| Module Name                                 | Analysis – Geographic Traffic Visualization                                                                                                                                                                                                                                                                 |
| Detailed Functional Requirement Description | The system shall provide a geographical visualization of network communications by mapping traffic endpoints to their corresponding geographic locations whenever location information is available. The visualization shall assist users in understanding the geographic distribution of network activity. |
| Priority                                    | Must Have                                                                                                                                                                                                                                                                                                   |

---

### FR-Analysis-08

| Field                                       | Content                                                                                                                                                                                                                       |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Analysis-08                                                                                                                                                                                                                |
| Module Name                                 | Analysis – Geographic Threat Visualization                                                                                                                                                                                    |
| Detailed Functional Requirement Description | The system shall visually distinguish anomalous or suspicious communications within geographic traffic visualizations in order to assist users in identifying potential threats and their geographic origins or destinations. |
| Priority                                    | Must Have                                                                                                                                                                                                                     |

---

### FR-Analysis-09

| Field                                       | Content                                                                                                                                                               |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Analysis-09                                                                                                                                                        |
| Module Name                                 | Analysis – Geographic Analysis Refresh                                                                                                                                |
| Detailed Functional Requirement Description | The system shall allow users to refresh geographic visualizations to ensure that newly collected monitoring data is incorporated into the displayed analysis results. |
| Priority                                    | Should Have                                                                                                                                                           |

---

### FR-Analysis-10

| Field                                       | Content                                                                                                                                                                                                           |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Analysis-10                                                                                                                                                                                                    |
| Module Name                                 | Analysis – Visualization Configuration                                                                                                                                                                            |
| Detailed Functional Requirement Description | The system shall allow users to select different analysis categories and visualization perspectives in order to customize the presentation of network monitoring data according to their analytical requirements. |
| Priority                                    | Should Have                                                                                                                                                                                                       |

---

### FR-Analysis-11

| Field                                       | Content                                                                                                                                                                                                                                      |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Analysis-11                                                                                                                                                                                                                               |
| Module Name                                 | Analysis – Location Resolution                                                                                                                                                                                                               |
| Detailed Functional Requirement Description | The system shall determine geographic location information for monitored network communications when such information is available and shall utilize the resulting location data to support geographic analysis and visualization functions. |
| Priority                                    | Must Have                                                                                                                                                                                                                                    |

---

### FR-Analysis-12

| Field                                       | Content                                                                                                                                                                                                               |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Analysis-12                                                                                                                                                                                                        |
| Module Name                                 | Analysis – Analysis Synchronization                                                                                                                                                                                   |
| Detailed Functional Requirement Description | The system shall continuously synchronize analytical visualizations with the most recent monitoring data in order to ensure that displayed analysis results accurately reflect the current state of network activity. |
| Priority                                    | Should Have                                                                                                                                                                                                           |

---

### FR-Analysis-13

| Field                                       | Content                                                                                                                                                                                |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requirement ID                              | FR-Analysis-13                                                                                                                                                                         |
| Module Name                                 | Analysis – Module Navigation                                                                                                                                                           |
| Detailed Functional Requirement Description | The system shall allow users to navigate between the Analysis, Home, Tools, and Incident Response modules without interrupting ongoing monitoring, analytical, or response activities. |
| Priority                                    | Must Have                                                                                                                                                                              |

---


# Non-Functional Requirements

| Requirement ID | Category        | Measurable / Quantifiable Target Criterion                                                                                                                                                                                                                   |
| -------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| NFR-01         | Performance     | The system shall process and display captured network traffic in near real time during active monitoring sessions and shall sustain processing of at least **1,000 packets per second** while maintaining continuous packet capture and interface updates.   |
| NFR-02         | Performance     | The system shall provide timely updates of monitoring information to support real-time situational awareness. Monitoring statistics, anomaly information, and traffic visualizations shall be refreshed within **2 seconds** of new data becoming available. |
| NFR-03         | Performance     | The system shall identify and report detected anomalous activity with minimal delay after traffic is processed. Detected anomalies shall be presented to the user within **5 seconds** of detection by the intrusion detection mechanism.                    |
| NFR-04         | Reliability     | The system shall maintain stable operation during extended monitoring sessions and shall operate continuously for at least **8 hours** without loss of functionality or unhandled runtime failures.                                                          |
| NFR-05         | Performance     | The system shall manage captured traffic efficiently to prevent excessive memory consumption. Memory utilization shall remain below **2 GB** during normal monitoring operations.                                                                            |
| NFR-06         | Scalability     | The system shall support analysis of large traffic datasets and maintain at least **15,000 captured packets** in active storage without preventing monitoring, filtering, visualization, or export operations.                                               |
| NFR-07         | Accuracy        | The system shall accurately identify packet protocols, traffic characteristics, and security events. Protocol classification and traffic categorization functions shall achieve at least **95% correctness** when evaluated using representative datasets.   |
| NFR-08         | Accuracy        | The traffic forecasting component shall only present prediction results when the forecasting model achieves an evaluation score of at least **0.50 R²** on the available dataset.                                                                            |
| NFR-09         | Availability    | The system shall maintain access to monitoring, analysis, and incident response functions and shall achieve at least **95% operational availability** during scheduled monitoring periods.                                                                   |
| NFR-10         | Security        | Security-sensitive mitigation operations, including traffic blocking and process termination, shall execute only when the required operating-system privileges are available.                                                                                |
| NFR-11         | Usability       | All primary monitoring, analysis, and incident response functions shall be accessible through the graphical user interface without requiring command-line interaction.                                                                                       |
| NFR-12         | Maintainability | The system architecture shall support replacement or extension of detection, prediction, and mitigation components without requiring modification of unrelated core system modules.                                                                          |
| NFR-13         | Compatibility   | The system shall support import and export of network traffic using standard packet-capture formats and structured data formats supported by the implemented system.                                                                                         |
| NFR-14         | Reliability     | Invalid user input, unsupported files, unavailable services, and non-critical runtime failures shall generate user-visible error notifications without causing application termination or loss of previously collected monitoring data.                      |
| NFR-15         | Auditability    | Security events and response actions shall be recorded with timestamps and remain available until explicitly cleared or exported by the user.                                                                                                                |

One thing I would still verify before putting this in the thesis is **NFR-07 (95% correctness)**. Unlike the R² threshold, packet storage limit, or memory limit—which seem directly tied to implementation/testing—a "95% correctness" figure should only be used if you actually measured it. If you did not perform a formal accuracy evaluation, I'd revise that one to avoid inventing a percentage. Everything else appears defensible from the system's implemented behavior.
