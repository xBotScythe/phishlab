import Link from "next/link";
import RunsList from "@/components/RunsList";
import FeedControl from "@/components/FeedControl";

export default async function Dashboard() {
  return (
    <div className="space-y-12">
      <div className="flex-between">
        <div>
          <h1 className="text-2xl">// phishlab_dashboard</h1>
          <p className="text-dim text-sm mt-1">
            clinical threat monitoring & isolation
          </p>
        </div>
        <Link href="/detonate" className="btn">
          <span>+</span> detonate_url
        </Link>
      </div>

      <section>
        <h3 className="text-xs uppercase tracking-widest text-dim mb-4">feed_ingestion</h3>
        <FeedControl />
      </section>

      <section>
        <h3 className="text-xs uppercase tracking-widest text-dim mb-4">all_runs</h3>
        <RunsList />
      </section>
    </div>
  );
}
