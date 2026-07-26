// ========================= App.jsx =========================

import React, { useState, useEffect } from 'react';

import {
  Activity,
  AlertTriangle,
  ShieldCheck,
  Clock,
  Server,
  Eye,
  CheckCircle
} from 'lucide-react';

import './index.css';

function App() {

  // =====================================================
  // STATES
  // =====================================================

  const [logs, setLogs] = useState([]);

  const [loading, setLoading] = useState(true);

  const [lastUpdated, setLastUpdated] = useState(new Date());

  // =====================================================
  // FETCH LOGS
  // =====================================================

  useEffect(() => {

    const fetchLogs = async () => {

      try {

        const response = await fetch(
          "http://127.0.0.1:9090/analyze_logs"
        );

        const data = await response.json();

        console.log(data);

        // IMPORTANT
        // replace logs fully
        setLogs([...(data.results || [])]);

        setLastUpdated(new Date());

      } catch (err) {

        console.error("FETCH ERROR:", err);

      } finally {

        setLoading(false);

      }
    };

    // FETCH ONLY ONCE
    fetchLogs();

  }, []);

  // =====================================================
  // LOADING
  // =====================================================

  if (loading && logs.length === 0) {

    return (

      <div className="loader-container">

        <Activity
          size={48}
          className="animate-pulse"
          color="var(--accent-color)"
        />

        <h2>Initializing KLEOS System...</h2>

      </div>
    );
  }

  // =====================================================
  // COUNTS
  // =====================================================

  const totalLogs = logs.length;

  const highRiskCount = logs.filter(
    (log) => log.risk === "HIGH"
  ).length;

  const lowRiskCount = logs.filter(
    (log) => log.risk === "LOW"
  ).length;

  const normalCount = logs.filter(
    (log) => log.risk === "NORMAL"
  ).length;

  // =====================================================
  // UI
  // =====================================================

  return (

    <div className="dashboard-container">

      {/* ================================================= */}
      {/* HEADER */}
      {/* ================================================= */}

      <header className="header">

        <div>

          <h1>KLEOS 2.0 Security Operations</h1>

          <p
            style={{
              color: 'var(--text-secondary)',
              marginTop: '0.5rem'
            }}
          >
            Real-time NLP Log Analysis
          </p>

        </div>

        <div className="badge">

          <Server size={16} />

          System Active

        </div>

      </header>

      {/* ================================================= */}
      {/* METRICS */}
      {/* ================================================= */}

      <div className="metrics-grid">

        {/* TOTAL */}

        <div className="glass-card">

          <h3 className="metric-title">

            <Activity
              size={18}
              color="var(--accent-color)"
            />

            Total Logs

          </h3>

          <p className="metric-value">

            {totalLogs}

          </p>

        </div>

        {/* HIGH */}

        <div
          className="glass-card"
          style={{
            borderColor: 'rgba(239,68,68,0.4)'
          }}
        >

          <h3 className="metric-title">

            <AlertTriangle
              size={18}
              color="red"
            />

            High Risk

          </h3>

          <p
            className="metric-value"
            style={{ color: 'red' }}
          >

            {highRiskCount}

          </p>

        </div>

        {/* LOW */}

        <div
          className="glass-card"
          style={{
            borderColor: 'rgba(255,165,0,0.4)'
          }}
        >

          <h3 className="metric-title">

            <AlertTriangle
              size={18}
              color="orange"
            />

            Low Risk

          </h3>

          <p
            className="metric-value"
            style={{ color: 'orange' }}
          >

            {lowRiskCount}

          </p>

        </div>

        {/* NORMAL */}

        <div className="glass-card">

          <h3 className="metric-title">

            <ShieldCheck
              size={18}
              color="var(--success-color)"
            />

            Normal Events

          </h3>

          <p className="metric-value">

            {normalCount}

          </p>

        </div>

      </div>

      {/* ================================================= */}
      {/* TABLE */}
      {/* ================================================= */}

      <div className="glass-card">

        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '1.5rem'
          }}
        >

          <h2
            style={{
              margin: 0,
              fontSize: '1.25rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}
          >

            <Eye size={20} />

            Live Monitoring Feed

          </h2>

          <span
            style={{
              fontSize: '0.875rem',
              color: 'var(--text-secondary)',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}
          >

            <Clock size={14} />

            Last Update:
            {lastUpdated.toLocaleTimeString()}

          </span>

        </div>

        {/* ================================================= */}
        {/* TABLE CONTENT */}
        {/* ================================================= */}

        <div className="table-container">

          <table>

            <thead>

              <tr>

                <th style={{ width: '15%' }}>
                  Status
                </th>

                <th style={{ width: '15%' }}>
                  Risk
                </th>

                <th style={{ width: '70%' }}>
                  Raw Log Entry
                </th>

              </tr>

            </thead>

            <tbody>

              {logs.map((log, index) => (

                <tr key={index}>

                  {/* STATUS */}

                  <td>

                    {log.risk === "HIGH" ? (

                      <span
                        className="status-indicator status-anomaly"
                      >

                        <AlertTriangle size={12} />

                        HIGH

                      </span>

                    ) : log.risk === "LOW" ? (

                      <span
                        className="status-indicator"
                        style={{
                          backgroundColor: 'orange',
                          color: 'white'
                        }}
                      >

                        <AlertTriangle size={12} />

                        LOW

                      </span>

                    ) : (

                      <span
                        className="status-indicator status-normal"
                      >

                        <CheckCircle size={12} />

                        NORMAL

                      </span>

                    )}

                  </td>

                  {/* RISK */}

                  <td>

                    <span
                      style={{
                        color:
                          log.risk === "HIGH"
                            ? "red"
                            : log.risk === "LOW"
                            ? "orange"
                            : "var(--text-secondary)",

                        fontFamily: 'monospace'
                      }}
                    >

                      {log.risk}

                    </span>

                  </td>

                  {/* RAW LOG */}

                  <td className="log-text">

                    {JSON.stringify(log.log)}

                  </td>

                </tr>

              ))}

              {/* EMPTY */}

              {logs.length === 0 && (

                <tr>

                  <td
                    colSpan="3"
                    style={{
                      textAlign: 'center',
                      color: 'var(--text-secondary)',
                      padding: '3rem 1rem'
                    }}
                  >

                    No logs ingested yet...

                  </td>

                </tr>

              )}

            </tbody>

          </table>

        </div>

      </div>

    </div>
  );
}

export default App;