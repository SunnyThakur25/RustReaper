const { useState, useEffect } = React;

const ProgressBar = () => {
    const [parseProgress, setParseProgress] = useState(0);
    const [analyzeProgress, setAnalyzeProgress] = useState(0);
    const [artifactCount, setArtifactCount] = useState(0);
    const [artifacts, setArtifacts] = useState([]);
    const [filterType, setFilterType] = useState('');

    useEffect(() => {
        const ws = new WebSocket(`ws://${window.location.host}/ws`);
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            setParseProgress(data.parse_progress);
            setAnalyzeProgress(data.analyze_progress);
            setArtifactCount(data.artifact_count);
        };
        return () => ws.close();
    }, []);

    useEffect(() => {
        fetch('/api/artifacts')
            .then(res => res.json())
            .then(data => setArtifacts(data));
    }, [artifactCount]);

    const filteredArtifacts = filterType
        ? artifacts.filter(a => a.artifact_type === filterType)
        : artifacts;

    return (
        <div className="space-y-4">
            <h1 className="text-2xl font-bold text-center">RustReaper Analysis</h1>
            <div>
                <label className="block text-sm font-medium">Parsing Progress</label>
                <div className="w-full bg-gray-200 rounded-full h-4">
                    <div
                        className="bg-blue-600 h-4 rounded-full"
                        style={{ width: `${parseProgress}%` }}
                    ></div>
                </div>
                <p className="text-sm">{parseProgress.toFixed(2)}%</p>
            </div>
            <div>
                <label className="block text-sm font-medium">Analysis Progress</label>
                <div className="w-full bg-gray-200 rounded-full h-4">
                    <div
                        className="bg-green-600 h-4 rounded-full"
                        style={{ width: `${analyzeProgress}%` }}
                    ></div>
                </div>
                <p className="text-sm">{analyzeProgress.toFixed(2)}%</p>
            </div>
            <p className="text-lg">Artifacts Found: {artifactCount}</p>
            <div>
                <label className="block text-sm font-medium">Filter by Type</label>
                <select
                    className="border rounded p-2"
                    value={filterType}
                    onChange={(e) => setFilterType(e.target.value)}
                >
                    <option value="">All</option>
                    <option value="Hook">Hook</option>
                    <option value="IndirectHook">IndirectHook</option>
                    <option value="EncryptedPayload">EncryptedPayload</option>
                    <option value="Shellcode">Shellcode</option>
                    <option value="InjectedPE">InjectedPE</option>
                    <option value="SuspiciousString">SuspiciousString</option>
                </select>
            </div>
            <table className="w-full border-collapse">
                <thead>
                    <tr className="bg-gray-200">
                        <th className="border p-2">Address</th>
                        <th className="border p-2">Type</th>
                        <th className="border p-2">Description</th>
                        <th className="border p-2">Confidence</th>
                        <th className="border p-2">Entropy</th>
                    </tr>
                </thead>
                <tbody>
                    {filteredArtifacts.map((artifact, index) => (
                        <tr key={index} className="hover:bg-gray-100">
                            <td className="border p-2">0x{artifact.address.toString(16)}</td>
                            <td className="border p-2">{artifact.artifact_type}</td>
                            <td className="border p-2">{artifact.description}</td>
                            <td className="border p-2">{artifact.confidence.toFixed(2)}</td>
                            <td className="border p-2">{artifact.entropy ? artifact.entropy.toFixed(2) : 'N/A'}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
            <a
                href="/api/report"
                className="inline-block bg-blue-500 text-white px-4 py-2 rounded"
                download
            >
                Download Report
            </a>
        </div>
    );
};

ReactDOM.render(<ProgressBar />, document.getElementById('root'));