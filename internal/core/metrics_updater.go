package core

import (
	"time"
)

func StartMetricsUpdater() {
	go func() {
		for {
			// Count active sessions
			var count int64
			iter := TokenDB.Scan(Ctx, 0, "X-rauth-authtoken=*", 0).Iterator()
			for iter.Next(Ctx) {
				count++
			}
			ActiveSessionsGauge.Set(float64(count))
			time.Sleep(1 * time.Minute)
		}
	}()
}
