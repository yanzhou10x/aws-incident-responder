# Aws Incident Responder

### Resources
- [Flaws2 Defender Track](http://flaws2.cloud/defender.htm)

### Athena queries
- How many events are there for each kind of event?
  - ```sql
    SELECT eventname AS event_name,
           count(*) AS event_count
    FROM flaws2.cloudtrail
    GROUP BY eventname
    ORDER BY event_count DESC
    ```
    ![alt text](https://user-images.githubusercontent.com/38987117/78983251-d8217600-7af1-11ea-9a99-0e7fc6688167.png)
- What percentage of events are errors?
  - ```sql
    SELECT count(*)*100.0/(SELECT count(*) FROM flaws2.cloudtrail) AS event_error_percentage
    FROM flaws2.cloudtrail
    WHERE errorcode IS NOT NULL;
    ```
    ![alt text](https://user-images.githubusercontent.com/38987117/78983728-c2608080-7af2-11ea-9d1b-5f3a745c0b20.png)

- For each distinct User Identity Account ID, what is the mean time between events?
  - ```sql
    WITH events AS 
      (SELECT useridentity.accountid AS account_id,
              min(eventtime) OVER (PARTITION BY useridentity.accountid) AS min_event_timestamp, 
              max(eventtime) OVER (PARTITION BY useridentity.accountid) AS max_event_timestamp, 
              count(*) OVER (PARTITION BY useridentity.accountid) AS event_count
      FROM flaws2.cloudtrail
      WHERE useridentity.accountid IS NOT NULL)
    SELECT DISTINCT account_id,
          DATE_DIFF('second', from_iso8601_timestamp(min_event_timestamp), from_iso8601_timestamp(max_event_timestamp))*1.0/(event_count-1) AS mean_interval_in_second
    FROM events
    ```
    ![alt text](https://user-images.githubusercontent.com/38987117/78983889-15d2ce80-7af3-11ea-8248-ac69d8259afc.png)
